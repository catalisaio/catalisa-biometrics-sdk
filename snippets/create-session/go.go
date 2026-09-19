// Creates a liveness session (Go, stdlib only). Run: go run go.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	baseURL := os.Getenv("CATALISA_BIOMETRICS_URL")
	if baseURL == "" {
		baseURL = "https://api.biometrics.catalisa.app/v1"
	}
	payload, _ := json.Marshal(map[string]any{
		"flow":     "LIVENESS_ONLY",
		"purpose":  "abertura de conta",
		"metadata": map[string]string{"orderId": "123"},
	})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions", bytes.NewReader(payload))
	req.Header.Set("X-API-Key", os.Getenv("CATALISA_API_KEY"))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	var body struct {
		Data struct {
			SessionID string `json:"sessionId"`
			Handoff   struct {
				CaptureURL string `json:"captureUrl"`
			} `json:"handoff"`
		} `json:"data"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "Error %d: %s %s\n", res.StatusCode, body.Error, body.Message)
		os.Exit(1)
	}
	fmt.Println("sessionId:", body.Data.SessionID)
	fmt.Println("captureUrl:", body.Data.Handoff.CaptureURL)
}
