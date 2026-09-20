package biometrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"
)

// CaptureSubmission is a capture recorded by your own app instead of the hosted
// page. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24
// seconds; anything else is refused before the engine runs.
type CaptureSubmission struct {
	// Video is the recording of the challenge.
	Video []byte
	// VideoMIME is "video/webm" or "video/mp4".
	VideoMIME string
	// VideoFilename is cosmetic; defaults to challenge.webm.
	VideoFilename string
	// Telemetry is whatever your capture measured (timings, device signals). It
	// feeds the integrity checks; malformed telemetry is ignored, not refused.
	Telemetry map[string]any
	// Channel says where the capture came from: HOSTED, IFRAME, WIDGET or SDK.
	// A native app should send SDK. The server reconciles it with the request's
	// origin, so a wrong value here does not buy anything.
	Channel CaptureChannel
	// CapturedAt is when the recording ended. The server clamps it to ±5 min of
	// its own clock.
	CapturedAt *time.Time
}

// CaptureResult is what the capture endpoint answers. It is deliberately poorer
// than the session envelope: score, checks and the full decision never come
// back here, so the person in front of the camera cannot be told why they
// failed — that would turn the page into a fraud oracle.
type CaptureResult struct {
	SessionID   string        `json:"sessionId"`
	Status      SessionStatus `json:"status"`
	Attempt     int           `json:"attempt"`
	MaxAttempts int           `json:"maxAttempts"`
	// Reasons only comes on RETRY_ALLOWED, and only quality/gesture reasons —
	// enough to tell the person what to do differently.
	Reasons []Reason `json:"reasons,omitempty"`
	// Handoff comes when another attempt is allowed: a fresh token and challenge.
	Handoff *Handoff `json:"handoff,omitempty"`
}

// SubmitCapture uploads a capture recorded by your own app, authenticating with
// the session's captureToken (from Handoff) — NOT with the API key. The token is
// single use and bound to the attempt.
//
// Use this only when you record the video yourself. The hosted capture page,
// which Handoff.CaptureURL points to, already does all of it — including the
// quality checks that keep a useless recording from spending an attempt.
func (c *Client) SubmitCapture(ctx context.Context, sessionID, captureToken string, in CaptureSubmission) (*CaptureResult, error) {
	if captureToken == "" {
		return nil, &Error{Code: "UNAUTHORIZED", Message: "captureToken is required"}
	}
	if len(in.Video) == 0 {
		return nil, &Error{Code: "VALIDATION", Message: "Video is empty"}
	}
	mime := in.VideoMIME
	if mime == "" {
		mime = "video/webm"
	}
	filename := in.VideoFilename
	if filename == "" {
		filename = "challenge.webm"
	}

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	header := make(map[string][]string)
	header["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="video"; filename=%q`, filename)}
	header["Content-Type"] = []string{mime}
	part, err := form.CreatePart(header)
	if err != nil {
		return nil, &Error{Code: "VALIDATION", Message: err.Error()}
	}
	if _, err := part.Write(in.Video); err != nil {
		return nil, &Error{Code: "VALIDATION", Message: err.Error()}
	}
	if in.Telemetry != nil {
		raw, err := json.Marshal(in.Telemetry)
		if err != nil {
			return nil, &Error{Code: "VALIDATION", Message: "could not encode the telemetry: " + err.Error()}
		}
		_ = form.WriteField("telemetry", string(raw))
	}
	if in.Channel != "" {
		_ = form.WriteField("channel", in.Channel)
	}
	if in.CapturedAt != nil {
		_ = form.WriteField("capturedAt", in.CapturedAt.UTC().Format(time.RFC3339Nano))
	}
	if err := form.Close(); err != nil {
		return nil, &Error{Code: "VALIDATION", Message: err.Error()}
	}

	endpoint := c.opts.BaseURL + "/sessions/" + url.PathEscape(sessionID) + "/captures"
	ctx, cancel := context.WithTimeout(orBackground(ctx), c.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, &Error{Code: "VALIDATION", Message: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Content-Type", form.FormDataContentType())
	// The capture token authenticates this call on its own; the API key is not
	// sent, so an app can upload without ever holding the account's key.
	req.Header.Set("Authorization", "Bearer "+captureToken)

	res, err := c.http.Do(req)
	if err != nil {
		code, msg := "CONNECTION", "connection failed: "+err.Error()
		if ctx.Err() != nil {
			code, msg = "TIMEOUT", fmt.Sprintf("no answer within %s", c.opts.Timeout)
		}
		return nil, &Error{Status: 0, Code: code, Message: msg}
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, &Error{Status: 0, Code: "CONNECTION", Message: "could not read the answer: " + err.Error()}
	}
	if res.StatusCode >= 400 {
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)
		return nil, errorFromResponse(res.StatusCode, parsed, res.Header)
	}
	var out struct {
		Data CaptureResult `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &Error{Status: res.StatusCode, Code: "INTERNAL", Message: "unexpected answer: " + err.Error()}
	}
	return &out.Data, nil
}

// ServerEvidenceVerification is what the API answers when it checks the
// signature itself.
type ServerEvidenceVerification struct {
	Valid     bool    `json:"valid"`
	KeyID     string  `json:"keyId"`
	RetiredAt *string `json:"retiredAt"`
}

// VerifyEvidenceOnServer asks the API to check the evidence signature. Handy as
// a sanity check, but it trusts the same party that signed it: for an audit,
// verify offline with VerifyEvidence and the published keys.
func (c *Client) VerifyEvidenceOnServer(ctx context.Context, sessionID string) (*ServerEvidenceVerification, error) {
	var out struct {
		Data ServerEvidenceVerification `json:"data"`
	}
	err := c.do(ctx, request{
		method:     http.MethodGet,
		path:       "/sessions/" + url.PathEscape(sessionID) + "/evidence/verify",
		idempotent: true,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

func orBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
