// Minimal server that receives the Biometrics webhook and verifies the signature.
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	biometrics "github.com/catalisaio/catalisa-biometrics-sdk/packages/go"
)

func main() {
	var keys map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("CATALISA_WEBHOOK_KEYS")), &keys); err != nil {
		panic(err)
	}
	verifier := biometrics.NewWebhookVerifier(keys) // tolerance: 5 min

	http.HandleFunc("/webhooks/biometrics", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) // RAW body: re-encoding it breaks the signature

		event, err := verifier.Verify(r.Header, body)
		if err != nil {
			log.Println("webhook rejected:", err)
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		// event.ID is stable: use it for idempotency, a delivery can repeat
		if event.Type == biometrics.EventSessionCompleted {
			log.Printf("session %v → %v", event.Data["sessionId"], event.Data["outcome"])
		}

		w.WriteHeader(http.StatusOK) // answer fast; do the work afterwards
		_, _ = w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
