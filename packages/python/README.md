# catalisa-biometrics

Python SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- **Standard library only** (urllib, hashlib) — no runtime dependencies, Python 3.9+
- Webhook RSA-SHA256 and evidence Ed25519 verification implemented in pure Python (verification only; no private keys involved)
- Typed errors and safe retries, same semantics as the Node SDK

```bash
pip install catalisa-biometrics
```

## Quick start

```python
import os
from catalisa_biometrics import Biometrics

bio = Biometrics(os.environ["CATALISA_API_KEY"])

session = bio.sessions.create(flow="LIVENESS_ONLY", purpose="abertura de conta", metadata={"orderId": "123"})
capture_url = session["handoff"]["captureUrl"]  # send the person here (link, iframe or WebView)

envelope = bio.sessions.get(session["sessionId"])
if envelope["status"] == "APPROVED":
    ...
```

The result arrives **on your server** — via the `biometrics.session.completed` webhook or `sessions.get`. The capture page never reveals it to the person in front of the camera.

### Client options

| Argument | Default | |
|---|---|---|
| `api_key` | — | Sent as `X-API-Key` (organization or subaccount key) |
| `access_token` | — | Alternative: IAM access JWT (`Authorization: Bearer`) |
| `base_url` | `https://api.biometrics.catalisa.app/v1` | `STAGING_BASE_URL` = `https://biometrics.bb.stg.catalisa.app/biometrics/api/v1` |
| `timeout` | `30.0` | Seconds per request |
| `max_retries` | `2` | 429 always; 5xx/network only for reads |
| `subaccount_id` | — | Act on behalf of a subaccount (`X-Subaccount-Id`) |
| `transport` | urllib | Injectable `(method, url, headers, body, timeout) -> HttpResponse` |

### Methods

| Method | HTTP |
|---|---|
| `sessions.create(flow=, purpose=, **fields, idempotency_key=None)` | `POST /sessions` |
| `sessions.get(id)` | `GET /sessions/:id` |
| `sessions.list(page=, page_size=, status=, flow=, customer_id=, subject_cpf=, date_from=, date_to=, subaccount_id=)` | `GET /sessions` |
| `sessions.cancel(id)` | `POST /sessions/:id/cancel` |
| `sessions.evidence(id)` | `GET /sessions/:id/evidence` |
| `sessions.verify_evidence_on_server(id)` | `GET /sessions/:id/evidence/verify` |
| `evidence.keys()` | `GET /evidence-keys` |
| `evidence.verify(id)` | Verifies the Ed25519 evidence signature **locally** |

Responses are plain dicts with the server's field names (`sessionId`, `handoff`, `decision`, `checks`...).

## Webhooks

Deliveries are signed by the Catalisa Webhooks Engine with **RSA-SHA256 (PKCS#1 v1.5)** over `x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body`, header `x-webhook-signature: v1=<base64>`. Verify with the subscription's **public key**, selected by `x-webhook-key-id` (from `GET /webhooks-engine/api/v1/subscriptions/:id/keys`).

```python
from catalisa_biometrics import construct_event, WebhookVerificationError

PUBLIC_KEYS = {"whk_…": "-----BEGIN PUBLIC KEY-----\n…"}

# Flask
@app.post("/webhooks/biometrics")
def webhook():
    try:
        event = construct_event(request.get_data(), request.headers, PUBLIC_KEYS)
    except WebhookVerificationError as e:
        return e.code, 400
    if event["type"] == "biometrics.session.completed":
        handle(event["data"]["sessionId"], event["data"]["outcome"])
    return "ok"
```

- Pass the **raw body** (`request.get_data()` in Flask, `request.body` in Django, `await request.body()` in FastAPI).
- The timestamp tolerance defaults to 300 s (`tolerance_seconds=`); the server does not reject old deliveries.
- Deduplicate by the body's `id`, not by `x-webhook-id` (it changes on every retry).
- `verify_webhook(...)` returns a bool; `check_webhook(...)` returns the failure reason.

## Errors

| Class | When |
|---|---|
| `AuthenticationError` | 401 |
| `QuotaExceededError` | 402 `QUOTA_EXCEEDED` (`e.details["used"]`, `e.details["monthlyQuota"]`) |
| `SubaccountSuspendedError` | 403 `SUBACCOUNT_SUSPENDED` |
| `PermissionDeniedError` | Other 403 |
| `ValidationError` | 400 / 413 / 415 / 422 |
| `NotFoundError` | 404 |
| `RateLimitError` | 429 (`e.retry_after`) |
| `ServerError` | 5xx |
| `APIConnectionError` | No response (`e.code` = `TIMEOUT` or `CONNECTION`) |
| `WebhookVerificationError` | Webhook not authentic |

All inherit from `BiometricsError` (`status`, `code`, `request_id`, `details`, `body`).

## License

MIT
