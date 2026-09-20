// go get github.com/catalisaio/catalisa-biometrics-sdk/packages/go
package main

import (
	"context"
	"fmt"
	"os"

	biometrics "github.com/catalisaio/catalisa-biometrics-sdk/packages/go"
)

func main() {
	bio, err := biometrics.New(biometrics.Options{
		APIKey:  os.Getenv("CATALISA_API_KEY"),
		BaseURL: os.Getenv("CATALISA_BIOMETRICS_URL"), // empty = the public API
	})
	if err != nil {
		panic(err)
	}

	session, err := bio.CreateSession(context.Background(), biometrics.CreateSessionInput{
		Flow:     biometrics.FlowLivenessOnly,
		Purpose:  "abertura de conta",
		Metadata: map[string]string{"orderId": "123"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Println("sessionId:", session.SessionID)
	fmt.Println("captureUrl:", session.Handoff.CaptureURL) // send the person here
}
