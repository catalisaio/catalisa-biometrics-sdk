package biometrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc, tweak func(*Options)) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	opts := Options{APIKey: "bio_test_key", BaseURL: server.URL, sleep: func(time.Duration) {}}
	if tweak != nil {
		tweak(&opts)
	}
	client, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

func TestNewRequiresCredential(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a client without a key should not be built")
	}
	if _, err := New(Options{AccessToken: "jwt"}); err != nil {
		t.Fatalf("a JWT is a valid credential: %v", err)
	}
}

func TestCreateSessionSendsKeyAndReturnsEnvelope(t *testing.T) {
	var gotPath, gotKey, gotSubaccount, gotIdem string
	var gotBody map[string]any
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey = r.URL.Path, r.Header.Get("X-API-Key")
		gotSubaccount, gotIdem = r.Header.Get("X-Subaccount-Id"), r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"sessionId":"s1","status":"SESSION_OPEN","environment":"test","provider":"MOCK","handoff":{"captureUrl":"https://capture/x","captureToken":"tok"}}}`))
	}, func(o *Options) { o.SubaccountID = "sub-1" })

	session, err := client.CreateSession(context.Background(), CreateSessionInput{
		Flow: FlowLivenessOnly, Purpose: "abertura de conta", IdempotencyKey: "key-1",
		Metadata: map[string]string{"orderId": "123"},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if gotPath != "/sessions" || gotKey != "bio_test_key" || gotSubaccount != "sub-1" || gotIdem != "key-1" {
		t.Fatalf("request went out wrong: %s %s %s %s", gotPath, gotKey, gotSubaccount, gotIdem)
	}
	if gotBody["flow"] != "LIVENESS_ONLY" || gotBody["purpose"] != "abertura de conta" {
		t.Fatalf("body went out wrong: %v", gotBody)
	}
	if session.SessionID != "s1" || session.Handoff == nil || session.Handoff.CaptureURL != "https://capture/x" {
		t.Fatalf("envelope came back wrong: %+v", session)
	}
	if !session.IsSandbox() {
		t.Fatal("a session with environment=test is a sandbox session")
	}
}

func TestErrorsCarryTheAPICode(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		sentinel error
		code     string
	}{
		{"quota", http.StatusPaymentRequired, `{"error":"PAYMENT_REQUIRED","message":"cota","details":{"code":"QUOTA_EXCEEDED","used":100,"monthlyQuota":100}}`, ErrQuotaExceeded, "QUOTA_EXCEEDED"},
		{"suspended", http.StatusForbidden, `{"error":"FORBIDDEN","message":"suspensa","details":{"code":"SUBACCOUNT_SUSPENDED"}}`, ErrPermissionDenied, "SUBACCOUNT_SUSPENDED"},
		{"unauthorized", http.StatusUnauthorized, `{"error":"UNAUTHORIZED","message":"chave inválida"}`, ErrAuthentication, "UNAUTHORIZED"},
		{"not found", http.StatusNotFound, `{"error":"NOT_FOUND","message":"sumiu"}`, ErrNotFound, "NOT_FOUND"},
		{"validation", http.StatusBadRequest, `{"error":"VALIDATION","message":"flow inválido"}`, ErrInvalidRequest, "VALIDATION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, nil)

			_, err := client.CreateSession(context.Background(), CreateSessionInput{Flow: FlowLivenessOnly, Purpose: "x"})
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("expected %v, got %v", tc.sentinel, err)
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Code != tc.code {
				t.Fatalf("expected code %s, got %v", tc.code, err)
			}
			if tc.name == "quota" && apiErr.Details["used"] != float64(100) {
				t.Fatalf("quota numbers should survive: %v", apiErr.Details)
			}
		})
	}
}

func TestAnHTMLErrorPageStillYieldsAUsableError(t *testing.T) {
	// A proxy in front of the API can answer HTML. The caller still needs a code.
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502</html>"))
	}, func(o *Options) { o.MaxRetries = 0 })

	_, err := client.GetSession(context.Background(), "s1")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "INTERNAL" || !errors.Is(err, ErrServer) {
		t.Fatalf("expected a server error, got %v", err)
	}
}

func TestReadsRetryButSessionCreationDoesNot(t *testing.T) {
	var reads, writes int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if atomic.AddInt32(&reads, 1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"INTERNAL"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"sessionId":"s1","status":"APPROVED"}}`))
			return
		}
		atomic.AddInt32(&writes, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"INTERNAL"}`))
	}, nil)

	if _, err := client.GetSession(context.Background(), "s1"); err != nil {
		t.Fatalf("a read should survive one 500: %v", err)
	}
	if reads != 2 {
		t.Fatalf("expected 2 read attempts, got %d", reads)
	}

	// Creating a session twice would open two sessions and spend the allowance twice.
	if _, err := client.CreateSession(context.Background(), CreateSessionInput{Flow: FlowLivenessOnly, Purpose: "x"}); err == nil {
		t.Fatal("a 500 on creation should surface")
	}
	if writes != 1 {
		t.Fatalf("session creation must not be retried; attempts: %d", writes)
	}
}

func TestRateLimitIsAlwaysRetried(t *testing.T) {
	var attempts int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"RATE_LIMITED"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"sessionId":"s2","status":"SESSION_OPEN"}}`))
	}, nil)

	// The rate limiter refuses before the handler runs, so nothing was done —
	// retrying is safe even for a write.
	session, err := client.CreateSession(context.Background(), CreateSessionInput{Flow: FlowLivenessOnly, Purpose: "x"})
	if err != nil || session.SessionID != "s2" {
		t.Fatalf("a 429 should be retried: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestListSendsPaginationAndFilters(t *testing.T) {
	var query string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[],"meta":{"total":0,"page":{"number":2,"size":50}}}`))
	}, nil)

	if _, err := client.ListSessions(context.Background(), ListSessionsInput{
		Page: 2, PageSize: 50, Status: StatusApproved, Environment: EnvironmentTest,
	}); err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, want := range []string{"page%5Bnumber%5D=2", "page%5Bsize%5D=50", "status=APPROVED", "environment=test"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query %q is missing %q", query, want)
		}
	}
}

func TestTimeoutBecomesAConnectionError(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
	}, func(o *Options) { o.Timeout = 20 * time.Millisecond; o.MaxRetries = 0 })

	_, err := client.GetSession(context.Background(), "s1")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "TIMEOUT" || !errors.Is(err, ErrConnection) {
		t.Fatalf("expected a timeout, got %v", err)
	}
}

func TestIsTerminal(t *testing.T) {
	for _, s := range []SessionStatus{StatusApproved, StatusRejected, StatusInconclusive, StatusExpired, StatusCancelled} {
		if !IsTerminal(s) {
			t.Fatalf("%s is terminal", s)
		}
	}
	for _, s := range []SessionStatus{StatusSessionOpen, StatusProcessing, StatusRetryAllowed, StatusError} {
		if IsTerminal(s) {
			t.Fatalf("%s is not terminal — the session can still change", s)
		}
	}
}

func TestSubmitCaptureUsesTheCaptureTokenNotTheAPIKey(t *testing.T) {
	var auth, apiKey, contentType string
	var fields = map[string]string{}
	var videoMIME, videoBytes string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth, apiKey, contentType = r.Header.Get("Authorization"), r.Header.Get("X-API-Key"), r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("multipart: %v", err)
		}
		for k, v := range r.MultipartForm.Value {
			fields[k] = v[0]
		}
		if fh := r.MultipartForm.File["video"]; len(fh) == 1 {
			videoMIME = fh[0].Header.Get("Content-Type")
			f, _ := fh[0].Open()
			b, _ := io.ReadAll(f)
			videoBytes = string(b)
		}
		_, _ = w.Write([]byte(`{"data":{"sessionId":"s1","status":"RETRY_ALLOWED","attempt":1,"maxAttempts":3,"reasons":["quality.too_dark"],"handoff":{"captureUrl":"https://capture/2","captureToken":"tok2"}}}`))
	}, nil)

	when := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	out, err := client.SubmitCapture(context.Background(), "s1", "capture-token", CaptureSubmission{
		Video: []byte("webm-bytes"), VideoMIME: "video/webm", Channel: "SDK",
		Telemetry: map[string]any{"fps": 30}, CapturedAt: &when,
	})
	if err != nil {
		t.Fatalf("SubmitCapture: %v", err)
	}
	// The app uploads with the session's token; the account key never leaves the server.
	if auth != "Bearer capture-token" || apiKey != "" {
		t.Fatalf("wrong credential: auth=%q apiKey=%q", auth, apiKey)
	}
	if !strings.HasPrefix(contentType, "multipart/form-data") || videoMIME != "video/webm" || videoBytes != "webm-bytes" {
		t.Fatalf("the video went out wrong: %s %s %q", contentType, videoMIME, videoBytes)
	}
	if fields["channel"] != "SDK" || fields["telemetry"] != `{"fps":30}` || !strings.HasPrefix(fields["capturedAt"], "2026-09-20T03:00:00") {
		t.Fatalf("fields went out wrong: %v", fields)
	}
	if out.Status != StatusRetryAllowed || out.Handoff == nil || out.Handoff.CaptureToken != "tok2" {
		t.Fatalf("result came back wrong: %+v", out)
	}
	// The capture answer never carries the decision detail.
	if len(out.Reasons) != 1 || out.Reasons[0] != "quality.too_dark" {
		t.Fatalf("expected the retry reason, got %v", out.Reasons)
	}
}

func TestSubmitCaptureRefusesAnEmptyVideoBeforeTheNetwork(t *testing.T) {
	var called bool
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { called = true }, nil)

	if _, err := client.SubmitCapture(context.Background(), "s1", "tok", CaptureSubmission{}); err == nil {
		t.Fatal("an empty capture is refused here, not by the server")
	}
	if _, err := client.SubmitCapture(context.Background(), "s1", "", CaptureSubmission{Video: []byte("x")}); err == nil {
		t.Fatal("without a capture token there is nothing to authenticate with")
	}
	if called {
		t.Fatal("neither case should have touched the network")
	}
}
