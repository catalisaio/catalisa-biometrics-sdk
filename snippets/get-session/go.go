// Reads the session envelope (Go, stdlib only). Run: SESSION_ID=… go run go.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

type Session struct {
	Status   string `json:"status"`
	Decision *struct {
		Outcome        string   `json:"outcome"`
		Reasons        []string `json:"reasons"`
		ReviewRequired bool     `json:"reviewRequired"`
	} `json:"decision"`
	Checks []struct {
		Kind      string  `json:"kind"`
		Status    string  `json:"status"`
		Score     float64 `json:"score"`
		Threshold float64 `json:"threshold"`
	} `json:"checks"`
}

func main() {
	baseURL := os.Getenv("CATALISA_BIOMETRICS_URL")
	if baseURL == "" {
		baseURL = "https://api.biometrics.catalisa.app/v1"
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/sessions/"+url.PathEscape(os.Getenv("SESSION_ID")), nil)
	req.Header.Set("X-API-Key", os.Getenv("CATALISA_API_KEY"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "Error", res.StatusCode)
		os.Exit(1)
	}

	var body struct{ Data Session `json:"data"` }
	json.NewDecoder(res.Body).Decode(&body)
	s := body.Data
	fmt.Println("status:", s.Status)
	if s.Decision != nil {
		fmt.Println("decision:", s.Decision.Outcome, s.Decision.Reasons)
		for _, c := range s.Checks {
			fmt.Printf(" - %s: %s (score %.2f / threshold %.2f)\n", c.Kind, c.Status, c.Score, c.Threshold)
		}
	}
}
