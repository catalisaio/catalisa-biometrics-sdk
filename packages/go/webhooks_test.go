package biometrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The vectors are shared by every SDK in this repository and were produced by
// the building block's own signing code, so "it passes here" means the same
// thing in each language.
type vectors struct {
	Webhook struct {
		Keys         map[string]string `json:"keys"`
		Headers      map[string]string `json:"headers"`
		Body         string            `json:"body"`
		Now          string            `json:"now"`
		TamperedBody string            `json:"tamperedBody"`
	} `json:"webhook"`
	Evidence struct {
		EvidenceKeysResponse struct {
			Data []EvidenceKey `json:"data"`
		} `json:"evidenceKeysResponse"`
		SessionID string `json:"sessionId"`
		Attempt   int    `json:"attempt"`
		Evidence  struct {
			BundleHash string            `json:"bundleHash"`
			Signature  EvidenceSignature `json:"signature"`
		} `json:"evidence"`
	} `json:"evidence"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vectors", "vectors.json"))
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	return v
}

func verifierAt(t *testing.T, v vectors) (*WebhookVerifier, http.Header, []byte) {
	t.Helper()
	now, err := time.Parse(time.RFC3339Nano, v.Webhook.Now)
	if err != nil {
		t.Fatalf("now: %v", err)
	}
	verifier := NewWebhookVerifier(v.Webhook.Keys)
	verifier.now = func() time.Time { return now }
	header := http.Header{}
	for k, val := range v.Webhook.Headers {
		header.Set(k, val)
	}
	return verifier, header, []byte(v.Webhook.Body)
}

func TestWebhookAcceptsAGenuineDelivery(t *testing.T) {
	v := loadVectors(t)
	verifier, header, body := verifierAt(t, v)

	event, err := verifier.Verify(header, body)
	if err != nil {
		t.Fatalf("a genuine delivery must verify: %v", err)
	}
	if event.ID == "" || event.Type == "" {
		t.Fatalf("the parsed event is empty: %+v", event)
	}
}

func TestWebhookRejectsATamperedBody(t *testing.T) {
	v := loadVectors(t)
	verifier, header, _ := verifierAt(t, v)

	_, err := verifier.Verify(header, []byte(v.Webhook.TamperedBody))
	var whErr *WebhookError
	if !errors.As(err, &whErr) || whErr.Failure != FailureInvalidSignature {
		t.Fatalf("a changed byte must fail the signature, got %v", err)
	}
	if !errors.Is(err, ErrWebhookVerification) {
		t.Fatal("every refusal wraps ErrWebhookVerification")
	}
}

func TestWebhookRejectsAnOldDelivery(t *testing.T) {
	v := loadVectors(t)
	verifier, header, body := verifierAt(t, v)
	// The engine does not refuse old deliveries — the receiver does, or a captured
	// delivery could be replayed forever.
	sent, _ := time.Parse(time.RFC3339Nano, v.Webhook.Headers["x-webhook-timestamp"])
	verifier.now = func() time.Time { return sent.Add(10 * time.Minute) }

	_, err := verifier.Verify(header, body)
	var whErr *WebhookError
	if !errors.As(err, &whErr) || whErr.Failure != FailureTimestampOutOfRange {
		t.Fatalf("expected the tolerance to refuse it, got %v", err)
	}

	// The same delivery passes when the receiver widens the window on purpose.
	verifier.Tolerance = time.Hour
	if _, err := verifier.Verify(header, body); err != nil {
		t.Fatalf("with an hour of tolerance it should pass: %v", err)
	}
}

func TestWebhookRejectsMissingHeadersAndUnknownKey(t *testing.T) {
	v := loadVectors(t)
	verifier, header, body := verifierAt(t, v)

	bare := http.Header{}
	if _, err := verifier.Verify(bare, body); err == nil {
		t.Fatal("no headers, no verification")
	}

	unknown := header.Clone()
	unknown.Set("x-webhook-key-id", "whk_not_mine")
	_, err := verifier.Verify(unknown, body)
	var whErr *WebhookError
	if !errors.As(err, &whErr) || whErr.Failure != FailureUnknownKeyID {
		t.Fatalf("expected UNKNOWN_KEY_ID, got %v", err)
	}

	wrongVersion := header.Clone()
	wrongVersion.Set("x-webhook-signature", "v2=abc")
	_, err = verifier.Verify(wrongVersion, body)
	if !errors.As(err, &whErr) || whErr.Failure != FailureUnsupportedSignature {
		t.Fatalf("expected UNSUPPORTED_SIGNATURE_VERSION, got %v", err)
	}
}

func TestVerifyEvidenceOffline(t *testing.T) {
	v := loadVectors(t)
	keys := v.Evidence.EvidenceKeysResponse.Data

	out := VerifyEvidence(v.Evidence.SessionID, v.Evidence.Attempt, v.Evidence.Evidence.BundleHash, v.Evidence.Evidence.Signature, keys)
	if !out.Valid || out.UnknownKey {
		t.Fatalf("the signed evidence must verify offline: %+v", out)
	}

	// Any change to what was signed breaks it — that is the whole point.
	if VerifyEvidence(v.Evidence.SessionID, v.Evidence.Attempt+1, v.Evidence.Evidence.BundleHash, v.Evidence.Evidence.Signature, keys).Valid {
		t.Fatal("another attempt number must not verify")
	}
	if VerifyEvidence(v.Evidence.SessionID, v.Evidence.Attempt, "0000", v.Evidence.Evidence.Signature, keys).Valid {
		t.Fatal("another bundle hash must not verify")
	}

	out = VerifyEvidence(v.Evidence.SessionID, v.Evidence.Attempt, v.Evidence.Evidence.BundleHash, EvidenceSignature{
		Alg: "Ed25519", KeyID: "ev-unknown", SignedAt: v.Evidence.Evidence.Signature.SignedAt, Value: v.Evidence.Evidence.Signature.Value,
	}, keys)
	if out.Valid || !out.UnknownKey {
		t.Fatalf("an unknown key is reported, not silently invalid: %+v", out)
	}
}
