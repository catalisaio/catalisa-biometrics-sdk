package biometrics

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Webhook deliveries are signed by the Catalisa Webhooks Engine:
//
//	message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
//	signature = RSA-SHA256 (PKCS#1 v1.5), base64, in x-webhook-signature as "v1=<base64>"
//	key       = the subscription's PUBLIC key, chosen by x-webhook-key-id
//
// The signature is asymmetric: there is no shared secret to leak. The server
// does not reject old deliveries, so the receiver enforces the time tolerance.

// WebhookFailure says why a delivery was refused.
type WebhookFailure string

const (
	FailureMissingHeaders       WebhookFailure = "MISSING_HEADERS"
	FailureTimestampInvalid     WebhookFailure = "TIMESTAMP_INVALID"
	FailureTimestampOutOfRange  WebhookFailure = "TIMESTAMP_OUT_OF_TOLERANCE"
	FailureUnknownKeyID         WebhookFailure = "UNKNOWN_KEY_ID"
	FailureUnsupportedSignature WebhookFailure = "UNSUPPORTED_SIGNATURE_VERSION"
	FailureInvalidSignature     WebhookFailure = "INVALID_SIGNATURE"
)

// ErrWebhookVerification wraps every refusal, so errors.Is can catch them all.
var ErrWebhookVerification = errors.New("webhook verification failed")

// WebhookError says which check failed. Answer 400 and do not process the body.
type WebhookError struct {
	Failure WebhookFailure
	Message string
}

func (e *WebhookError) Error() string {
	return fmt.Sprintf("biometrics webhook: %s: %s", e.Failure, e.Message)
}
func (e *WebhookError) Unwrap() error { return ErrWebhookVerification }

var failureMessages = map[WebhookFailure]string{
	FailureMissingHeaders:       "missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature",
	FailureTimestampInvalid:     "x-webhook-timestamp is not an ISO 8601 date",
	FailureTimestampOutOfRange:  "delivery is outside the time tolerance (possible replay)",
	FailureUnknownKeyID:         "no public key for this x-webhook-key-id",
	FailureUnsupportedSignature: "unsupported signature version (expected v1=)",
	FailureInvalidSignature:     "invalid signature",
}

func webhookErr(f WebhookFailure) *WebhookError {
	return &WebhookError{Failure: f, Message: failureMessages[f]}
}

// WebhookVerifier verifies deliveries against the subscription's public keys,
// keyed by their keyId (`GET /webhooks-engine/api/v1/subscriptions/{id}/keys`).
// A retired key stays in the map so deliveries in flight still verify.
type WebhookVerifier struct {
	// Keys maps keyId to the PEM public key.
	Keys map[string]string
	// Tolerance for the delivery timestamp. Zero means 5 minutes; use a negative
	// value to disable the check (not recommended — it allows replay).
	Tolerance time.Duration
	// now replaces the clock in tests.
	now func() time.Time
}

// NewWebhookVerifier builds a verifier with the default 5-minute tolerance.
func NewWebhookVerifier(keys map[string]string) *WebhookVerifier {
	return &WebhookVerifier{Keys: keys}
}

// Verify checks the signature over the RAW body — the bytes as they arrived. Do
// not decode and re-encode the JSON before verifying: any reordering or
// reformatting changes the bytes and the signature will not match.
//
// On success it returns the parsed event. Use event.ID for idempotency: a
// delivery can arrive more than once.
func (v *WebhookVerifier) Verify(header http.Header, body []byte) (*WebhookEvent, error) {
	id := header.Get("x-webhook-id")
	timestamp := header.Get("x-webhook-timestamp")
	keyID := header.Get("x-webhook-key-id")
	signature := header.Get("x-webhook-signature")
	if id == "" || timestamp == "" || keyID == "" || signature == "" {
		return nil, webhookErr(FailureMissingHeaders)
	}

	sentAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return nil, webhookErr(FailureTimestampInvalid)
	}
	tolerance := v.Tolerance
	if tolerance == 0 {
		tolerance = 5 * time.Minute
	}
	if tolerance > 0 {
		now := time.Now
		if v.now != nil {
			now = v.now
		}
		if drift := now().Sub(sentAt); drift > tolerance || drift < -tolerance {
			return nil, webhookErr(FailureTimestampOutOfRange)
		}
	}

	if !strings.HasPrefix(signature, "v1=") {
		return nil, webhookErr(FailureUnsupportedSignature)
	}
	pemKey, ok := v.Keys[keyID]
	if !ok {
		return nil, webhookErr(FailureUnknownKeyID)
	}
	publicKey, err := parsePublicKey(pemKey)
	if err != nil {
		return nil, webhookErr(FailureUnknownKeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(signature, "v1="))
	if err != nil {
		return nil, webhookErr(FailureInvalidSignature)
	}

	message := make([]byte, 0, len(id)+len(timestamp)+len(body)+2)
	message = append(message, id...)
	message = append(message, '\n')
	message = append(message, timestamp...)
	message = append(message, '\n')
	message = append(message, body...)
	digest := sha256.Sum256(message)

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, webhookErr(FailureInvalidSignature)
	}
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], raw); err != nil {
		return nil, webhookErr(FailureInvalidSignature)
	}

	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, &WebhookError{Failure: FailureInvalidSignature, Message: "signed body is not valid JSON: " + err.Error()}
	}
	return &event, nil
}

func parsePublicKey(pemKey string) (any, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// EvidenceVerification is the outcome of checking a signature offline.
type EvidenceVerification struct {
	Valid bool
	KeyID string
	// UnknownKey is true when no published key has this keyId.
	UnknownKey bool
	// RetiredAt is set when the signing key has since been retired. A signature
	// made before the retirement is still valid — this is for your audit trail.
	RetiredAt *string
}

// VerifyEvidence checks the evidence signature WITHOUT calling Catalisa. The
// message is `sessionID|attempt|bundleHash|signedAt`, signed with Ed25519.
// Attempt comes from the session envelope.
//
// This is what lets a third party — an auditor, a court — confirm that the
// decision bundle is the one Catalisa signed, years later, offline.
func VerifyEvidence(sessionID string, attempt int, bundleHash string, signature EvidenceSignature, keys []EvidenceKey) EvidenceVerification {
	out := EvidenceVerification{KeyID: signature.KeyID}
	var key *EvidenceKey
	for i := range keys {
		if keys[i].KeyID == signature.KeyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		out.UnknownKey = true
		return out
	}
	out.RetiredAt = key.RetiredAt
	if signature.Alg != "Ed25519" {
		return out
	}
	parsed, err := parsePublicKey(key.PublicKeyPEM)
	if err != nil {
		return out
	}
	edKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return out
	}
	raw, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return out
	}
	message := fmt.Sprintf("%s|%d|%s|%s", sessionID, attempt, bundleHash, signature.SignedAt)
	out.Valid = ed25519.Verify(edKey, []byte(message), raw)
	return out
}
