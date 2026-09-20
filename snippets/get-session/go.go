package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	biometrics "github.com/catalisaio/catalisa-biometrics-sdk/packages/go"
)

func main() {
	bio, _ := biometrics.New(biometrics.Options{
		APIKey:  os.Getenv("CATALISA_API_KEY"),
		BaseURL: os.Getenv("CATALISA_BIOMETRICS_URL"),
	})

	session, err := bio.GetSession(context.Background(), os.Getenv("SESSION_ID"))
	if errors.Is(err, biometrics.ErrNotFound) {
		fmt.Println("Session not found (or owned by another organization)")
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Println("status:", session.Status)
	if session.Decision != nil {
		reasons := strings.Join(session.Decision.Reasons, ", ")
		if reasons == "" {
			reasons = "(no reasons)"
		}
		fmt.Println("decision:", session.Decision.Outcome, reasons)
		for _, check := range session.Checks {
			fmt.Printf(" - %s: %s (score %v / threshold %v)\n", check.Kind, check.Status, check.Score, check.Threshold)
		}
	}
}
