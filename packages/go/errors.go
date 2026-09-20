package biometrics

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// Error is what every failed call returns. The API answers
// `{"error":"<code>","message":"...","details":{...}}`, so Code is the API's own
// word for what happened — compare against it, never against Message.
type Error struct {
	// Status is the HTTP status, or 0 when the request never reached the API.
	Status int
	// Code is the API error code (VALIDATION, NOT_FOUND, QUOTA_EXCEEDED…), or
	// TIMEOUT/CONNECTION when the request did not complete.
	Code string
	// Message is meant for a human reading a log, not for branching.
	Message string
	// Details carries whatever the API attached (field errors, quota numbers).
	Details map[string]any
	// RequestID is the `x-request-id` header, when the API sends one.
	RequestID string
	// RetryAfter is the `Retry-After` header on a 429, in seconds.
	RetryAfter int
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("biometrics: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("biometrics: %d %s: %s", e.Status, e.Code, e.Message)
}

// The sentinels below let a caller branch with errors.Is on the cases worth
// handling differently. Everything else is just an *Error with its Code.
var (
	// ErrAuthentication: the key is missing, wrong or revoked (401).
	ErrAuthentication = errors.New("authentication failed")
	// ErrPermissionDenied: the key is valid but may not do this (403). A
	// suspended subaccount arrives here with Code SUBACCOUNT_SUSPENDED.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrNotFound: no session with that id in this scope (404). A session from
	// another subaccount — or from the other environment — is also a 404, on
	// purpose: existence is not confirmed.
	ErrNotFound = errors.New("not found")
	// ErrInvalidRequest: the API refused the payload (400/422).
	ErrInvalidRequest = errors.New("invalid request")
	// ErrQuotaExceeded: the subaccount's monthly allowance is gone (402). A test
	// key never gets here — the sandbox spends no allowance.
	ErrQuotaExceeded = errors.New("quota exceeded")
	// ErrRateLimit: too many requests (429); see Error.RetryAfter.
	ErrRateLimit = errors.New("rate limited")
	// ErrServer: the API failed (5xx).
	ErrServer = errors.New("server error")
	// ErrConnection: the request never got an answer (network, DNS, timeout).
	ErrConnection = errors.New("connection failed")
)

// Unwrap maps the error onto the sentinel that fits, so errors.Is works.
func (e *Error) Unwrap() error {
	switch {
	case e.Code == "QUOTA_EXCEEDED" || e.Status == http.StatusPaymentRequired:
		return ErrQuotaExceeded
	case e.Status == http.StatusUnauthorized:
		return ErrAuthentication
	case e.Status == http.StatusForbidden:
		return ErrPermissionDenied
	case e.Status == http.StatusNotFound:
		return ErrNotFound
	case e.Status == http.StatusTooManyRequests:
		return ErrRateLimit
	case e.Status == http.StatusBadRequest || e.Status == http.StatusUnprocessableEntity:
		return ErrInvalidRequest
	case e.Status >= 500:
		return ErrServer
	case e.Status == 0:
		return ErrConnection
	}
	return nil
}

// errorFromResponse builds the error from what the API answered. A body that is
// not the expected envelope (an HTML error page from a proxy, say) still yields
// a usable Code from the status.
func errorFromResponse(status int, body map[string]any, header http.Header) *Error {
	e := &Error{Status: status, Code: codeForStatus(status), RequestID: header.Get("x-request-id")}
	if v, ok := body["error"].(string); ok && v != "" {
		e.Code = v
	}
	if v, ok := body["message"].(string); ok {
		e.Message = v
	}
	if v, ok := body["details"].(map[string]any); ok {
		e.Details = v
		// The API puts the machine-readable code inside details on the cases that
		// need numbers with them (quota, suspension).
		if c, ok := v["code"].(string); ok && c != "" {
			e.Code = c
		}
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	if status == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(header.Get("Retry-After")); err == nil {
			e.RetryAfter = s
		}
	}
	return e
}

func codeForStatus(status int) string {
	switch {
	case status == http.StatusBadRequest:
		return "VALIDATION"
	case status == http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case status == http.StatusPaymentRequired:
		return "QUOTA_EXCEEDED"
	case status == http.StatusForbidden:
		return "FORBIDDEN"
	case status == http.StatusNotFound:
		return "NOT_FOUND"
	case status == http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case status >= 500:
		return "INTERNAL"
	}
	return "ERROR"
}
