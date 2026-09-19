# Minimal server (stdlib only) that receives the Biometrics webhook and verifies the signature.
# CATALISA_WEBHOOK_KEYS = {"whk_…": "-----BEGIN PUBLIC KEY-----…"}
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from catalisa_biometrics import WebhookVerificationError, construct_event

PUBLIC_KEYS = json.loads(os.environ["CATALISA_WEBHOOK_KEYS"])


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhooks/biometrics":
            return self.send_error(404)
        raw_body = self.rfile.read(int(self.headers.get("Content-Length", 0)))  # RAW body
        try:
            event = construct_event(raw_body, self.headers, PUBLIC_KEYS)  # default tolerance: 300 s
        except WebhookVerificationError as e:
            print("webhook rejected:", e.code)
            self.send_response(400)
            self.end_headers()
            return
        # Idempotency: use event["id"], not the x-webhook-id header (it changes on every retry).
        if event["type"] == "biometrics.session.completed":
            print("session", event["data"]["sessionId"], "→", event["data"]["outcome"])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "3000"))), WebhookHandler).serve_forever()
