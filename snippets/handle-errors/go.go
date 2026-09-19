// Handles 402 (quota) and 403 (suspended subaccount) when creating a session (Go, stdlib only).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details struct {
		Code         string `json:"code"`
		Used         int    `json:"used"`
		MonthlyQuota int    `json:"monthlyQuota"`
	} `json:"details"`
}

func main() {
	baseURL := os.Getenv("CATALISA_BIOMETRICS_URL")
	if baseURL == "" {
		baseURL = "https://api.biometrics.catalisa.app/v1"
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions", strings.NewReader(`{"flow":"LIVENESS_ONLY","purpose":"abertura de conta"}`))
	req.Header.Set("X-API-Key", os.Getenv("CATALISA_API_KEY"))
	req.Header.Set("X-Subaccount-Id", os.Getenv("CATALISA_SUBACCOUNT_ID"))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusCreated {
		fmt.Println("ok: session created")
		return
	}
	var e apiError
	json.NewDecoder(res.Body).Decode(&e)
	switch {
	case res.StatusCode == http.StatusPaymentRequired && e.Details.Code == "QUOTA_EXCEEDED":
		fmt.Printf("blocked: QUOTA_EXCEEDED — monthly quota used (%d/%d)\n", e.Details.Used, e.Details.MonthlyQuota)
	case res.StatusCode == http.StatusForbidden && e.Details.Code == "SUBACCOUNT_SUSPENDED":
		fmt.Println("blocked: SUBACCOUNT_SUSPENDED — subaccount suspended")
	default:
		fmt.Fprintf(os.Stderr, "error %d: %s %s\n", res.StatusCode, e.Error, e.Details.Code)
		os.Exit(1)
	}
}
