// Receives the Biometrics webhook and verifies the signature (Go 1.22+, stdlib only).
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var publicKeys = map[string]*rsa.PublicKey{}

func verify(r *http.Request, body []byte) bool {
	id, timestamp := r.Header.Get("x-webhook-id"), r.Header.Get("x-webhook-timestamp")
	keyID, signature := r.Header.Get("x-webhook-key-id"), r.Header.Get("x-webhook-signature")
	sentAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if id == "" || err != nil || time.Since(sentAt).Abs() > 300*time.Second || !strings.HasPrefix(signature, "v1=") {
		return false
	}
	key, ok := publicKeys[keyID]
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature[3:])
	if err != nil {
		return false
	}
	digest := sha256.Sum256(append([]byte(id+"\n"+timestamp+"\n"), body...))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
}

func main() {
	var pems map[string]string
	json.Unmarshal([]byte(os.Getenv("CATALISA_WEBHOOK_KEYS")), &pems)
	for keyID, p := range pems {
		block, _ := pem.Decode([]byte(p))
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys[keyID] = key.(*rsa.PublicKey)
	}

	http.HandleFunc("POST /webhooks/biometrics", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) // RAW body
		if !verify(r, body) {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		var event struct {
			ID   string         `json:"id"` // idempotency: this one, not the x-webhook-id header
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		json.Unmarshal(body, &event)
		log.Println(event.Type, event.Data["sessionId"], event.Data["outcome"])
		w.Write([]byte("ok"))
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
