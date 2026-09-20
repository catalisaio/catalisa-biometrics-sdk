// Package biometrics is the Go SDK for Catalisa Biometrics: liveness and
// face-match sessions, signed evidence and webhook verification.
//
// The flow never trusts the browser:
//
//  1. your server creates a session and gets handoff.CaptureURL;
//  2. the person opens that URL (tab, iframe or WebView) and does the challenge;
//  3. the decision reaches your server through the webhook, or through Get.
//
// The capture page never shows the result to the person in front of the camera,
// on purpose: it would be a fraud oracle. Never decide anything from front-end
// events.
package biometrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public API. Point BaseURL elsewhere to reach another
// installation (a dedicated deployment, for instance).
const DefaultBaseURL = "https://api.biometrics.catalisa.app/v1"

// Version of this SDK, sent in the User-Agent.
const Version = "0.1.0"

// Options configures the client. APIKey is the only required field.
type Options struct {
	// APIKey is the key issued in the console. A key beginning a session decides
	// its world: a test key runs the sandbox.
	APIKey string
	// AccessToken uses an IAM JWT instead of an API key (console-style access).
	AccessToken string
	// BaseURL defaults to DefaultBaseURL.
	BaseURL string
	// Timeout per attempt. Defaults to 30s.
	Timeout time.Duration
	// MaxRetries for reads and for 429. Defaults to 2.
	MaxRetries int
	// SubaccountID acts on behalf of a subaccount when holding an organization
	// key. With a subaccount key the scope is already bound and this is ignored.
	SubaccountID string
	// HTTPClient replaces the transport (tests, proxies, instrumentation).
	HTTPClient *http.Client
	// UserAgent overrides the default.
	UserAgent string
	// sleep replaces the wait between attempts in tests.
	sleep func(time.Duration)
}

// Client talks to the API. It is safe for concurrent use.
type Client struct {
	opts Options
	http *http.Client
}

// New builds a client. It fails only when no credential is given — everything
// else has a sane default.
func New(opts Options) (*Client, error) {
	if opts.APIKey == "" && opts.AccessToken == "" {
		return nil, fmt.Errorf("biometrics: APIKey (or AccessToken) is required")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 2
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "catalisa-biometrics-go/" + Version
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{opts: opts, http: httpClient}, nil
}

// CreateSession opens a session and returns the envelope, with Handoff filled in.
//
// It is never retried on a 5xx or a network failure: the server does not
// deduplicate by Idempotency-Key yet, and a retry could open two sessions (and
// spend the allowance twice). A 429 is retried, because the rate limiter
// refuses before anything happens.
func (c *Client) CreateSession(ctx context.Context, in CreateSessionInput) (*Session, error) {
	headers := map[string]string{}
	if in.IdempotencyKey != "" {
		headers["Idempotency-Key"] = in.IdempotencyKey
	}
	var out struct {
		Data Session `json:"data"`
	}
	err := c.do(ctx, request{method: http.MethodPost, path: "/sessions", body: in, headers: headers}, &out)
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// GetSession reads a session. A session from another subaccount — or from the
// other environment — answers NotFound, on purpose.
func (c *Client) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var out struct {
		Data Session `json:"data"`
	}
	err := c.do(ctx, request{method: http.MethodGet, path: "/sessions/" + url.PathEscape(sessionID), idempotent: true}, &out)
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// ListSessions lists sessions, newest first.
func (c *Client) ListSessions(ctx context.Context, in ListSessionsInput) (*SessionList, error) {
	q := url.Values{}
	if in.Page > 0 {
		q.Set("page[number]", strconv.Itoa(in.Page))
	}
	if in.PageSize > 0 {
		q.Set("page[size]", strconv.Itoa(in.PageSize))
	}
	for k, v := range map[string]string{
		"status": in.Status, "flow": in.Flow, "customerId": in.CustomerID,
		"subjectCpf": in.SubjectCPF, "from": in.From, "to": in.To,
		"subaccountId": in.SubaccountID, "environment": in.Environment,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var out SessionList
	err := c.do(ctx, request{method: http.MethodGet, path: "/sessions", query: q, idempotent: true}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelSession closes a session that has not settled yet. The allowance slot
// comes back: a cancelled session does not count.
func (c *Client) CancelSession(ctx context.Context, sessionID string) (*Session, error) {
	var out struct {
		Data Session `json:"data"`
	}
	err := c.do(ctx, request{method: http.MethodPost, path: "/sessions/" + url.PathEscape(sessionID) + "/cancel"}, &out)
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// SessionEvidence returns the signed evidence with short-lived download URLs.
// Verify the signature offline with VerifyEvidence.
func (c *Client) SessionEvidence(ctx context.Context, sessionID string) (*EvidenceWithURLs, error) {
	var out struct {
		Data EvidenceWithURLs `json:"data"`
	}
	err := c.do(ctx, request{method: http.MethodGet, path: "/sessions/" + url.PathEscape(sessionID) + "/evidence", idempotent: true}, &out)
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// EvidenceKeys lists the published signing keys, retired ones included, so old
// evidence still verifies.
func (c *Client) EvidenceKeys(ctx context.Context) ([]EvidenceKey, error) {
	var out struct {
		Data []EvidenceKey `json:"data"`
	}
	err := c.do(ctx, request{method: http.MethodGet, path: "/evidence-keys", idempotent: true}, &out)
	if err != nil {
		return nil, err
	}
	return out.Data, nil
}

type request struct {
	method     string
	path       string
	query      url.Values
	body       any
	headers    map[string]string
	idempotent bool
}

func (c *Client) do(ctx context.Context, req request, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := c.opts.BaseURL + req.path
	if len(req.query) > 0 {
		endpoint += "?" + req.query.Encode()
	}
	var payload []byte
	if req.body != nil {
		var err error
		payload, err = json.Marshal(req.body)
		if err != nil {
			return &Error{Code: "VALIDATION", Message: fmt.Sprintf("could not encode the body: %v", err)}
		}
	}

	for attempt := 0; ; attempt++ {
		err := c.once(ctx, endpoint, req, payload, out)
		if err == nil {
			return nil
		}
		apiErr, ok := err.(*Error)
		if !ok || attempt >= c.opts.MaxRetries || ctx.Err() != nil {
			return err
		}
		// 429 is always safe to retry: nothing ran. 5xx and network failures are
		// retried only for reads.
		retryable := apiErr.Status == http.StatusTooManyRequests ||
			(req.idempotent && (apiErr.Status >= 500 || apiErr.Status == 0))
		if !retryable {
			return err
		}
		wait := backoff(attempt, apiErr)
		if c.opts.sleep != nil {
			c.opts.sleep(wait)
			continue
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
}

func (c *Client) once(ctx context.Context, endpoint string, req request, payload []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.method, endpoint, bodyReader)
	if err != nil {
		return &Error{Code: "VALIDATION", Message: err.Error()}
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.opts.UserAgent)
	if payload != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if c.opts.AccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.opts.AccessToken)
	} else {
		httpReq.Header.Set("X-API-Key", c.opts.APIKey)
	}
	if c.opts.SubaccountID != "" {
		httpReq.Header.Set("X-Subaccount-Id", c.opts.SubaccountID)
	}
	for k, v := range req.headers {
		httpReq.Header.Set(k, v)
	}

	res, err := c.http.Do(httpReq)
	if err != nil {
		code, msg := "CONNECTION", "connection failed: "+err.Error()
		if ctx.Err() != nil {
			code, msg = "TIMEOUT", fmt.Sprintf("no answer within %s", c.opts.Timeout)
		}
		return &Error{Status: 0, Code: code, Message: msg}
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return &Error{Status: 0, Code: "CONNECTION", Message: "could not read the answer: " + err.Error()}
	}
	if res.StatusCode >= 400 {
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return errorFromResponse(res.StatusCode, body, res.Header)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &Error{Status: res.StatusCode, Code: "INTERNAL", Message: "unexpected answer: " + err.Error()}
	}
	return nil
}

func backoff(attempt int, err *Error) time.Duration {
	if err.RetryAfter > 0 {
		wait := time.Duration(err.RetryAfter) * time.Second
		if wait > 30*time.Second {
			return 30 * time.Second
		}
		return wait
	}
	base := 500 * time.Millisecond * time.Duration(1<<attempt)
	jitter := time.Duration(rand.Int63n(int64(base) / 4))
	if base+jitter > 8*time.Second {
		return 8 * time.Second
	}
	return base + jitter
}
