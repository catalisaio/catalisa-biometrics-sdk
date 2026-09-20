package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	biometrics "github.com/catalisaio/catalisa-biometrics-sdk/packages/go"
)

func main() {
	bio, _ := biometrics.New(biometrics.Options{
		APIKey:  os.Getenv("CATALISA_API_KEY"),
		BaseURL: os.Getenv("CATALISA_BIOMETRICS_URL"),
		// organization key acting on behalf of the subaccount
		SubaccountID: os.Getenv("CATALISA_SUBACCOUNT_ID"),
	})

	session, err := bio.CreateSession(context.Background(), biometrics.CreateSessionInput{
		Flow:    biometrics.FlowLivenessOnly,
		Purpose: "abertura de conta",
	})
	if err == nil {
		fmt.Println("ok:", session.Handoff.CaptureURL)
		return
	}

	var apiErr *biometrics.Error
	errors.As(err, &apiErr)
	switch {
	case errors.Is(err, biometrics.ErrQuotaExceeded): // 402
		fmt.Printf("blocked: %s — monthly quota used (%v/%v)\n",
			apiErr.Code, apiErr.Details["used"], apiErr.Details["monthlyQuota"])
	case apiErr != nil && apiErr.Code == "SUBACCOUNT_SUSPENDED": // 403
		fmt.Printf("blocked: %s — subaccount suspended\n", apiErr.Code)
	case errors.Is(err, biometrics.ErrRateLimit): // the SDK already retried
		retry := apiErr.RetryAfter
		if retry == 0 {
			retry = 1
		}
		fmt.Printf("rate limited; retry in %d s\n", retry)
	default:
		fmt.Fprintf(os.Stderr, "error %d: %s (requestId %s)\n", apiErr.Status, apiErr.Code, apiErr.RequestID)
		os.Exit(1)
	}
}
