# @catalisa/biometrics

Node.js SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- Zero runtime dependencies (native `fetch` and `node:crypto`), Node.js **18+**
- ESM + CommonJS + TypeScript types
- Typed errors, safe retries, offline verification of the Ed25519 evidence signature

```bash
npm install @catalisa/biometrics
```

## How the flow works

1. **Your server** creates a session and receives `handoff.captureUrl`.
2. The person opens the `captureUrl` (link, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or via `sessions.get`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything based on front-end events.

## Quick start

```ts
import { Biometrics } from '@catalisa/biometrics'

const bio = new Biometrics({ apiKey: process.env.CATALISA_API_KEY })

const session = await bio.sessions.create({
  flow: 'LIVENESS_ONLY',
  purpose: 'abertura de conta',
  metadata: { orderId: '123' },
})
// send the person to session.handoff.captureUrl

const envelope = await bio.sessions.get(session.sessionId)
if (envelope.status === 'APPROVED') {
  // proceed
}
```

CommonJS: `const { Biometrics } = require('@catalisa/biometrics')`.

### Options

| Option | Default | |
|---|---|---|
| `apiKey` | — | API key, sent as `X-API-Key`. Organization or subaccount key |
| `accessToken` | — | Alternative: IAM access JWT, sent as `Authorization: Bearer` |
| `baseUrl` | `https://api.biometrics.catalisa.app/v1` | Staging: `https://biometrics.bb.stg.catalisa.app/biometrics/api/v1` |
| `timeoutMs` | `30000` | Per request |
| `maxRetries` | `2` | See [Retries](#retries) |
| `subaccountId` | — | Act on behalf of a subaccount with an organization key (`X-Subaccount-Id`) |
| `fetch` | global `fetch` | Custom fetch (proxy, tests) |

## API

| Method | HTTP |
|---|---|
| `sessions.create(params, { idempotencyKey? })` | `POST /sessions` |
| `sessions.get(id)` | `GET /sessions/:id` |
| `sessions.list({ page, pageSize, status, flow, customerId, subjectCpf, from, to, subaccountId })` | `GET /sessions` |
| `sessions.cancel(id)` | `POST /sessions/:id/cancel` |
| `sessions.evidence(id)` | `GET /sessions/:id/evidence` (hashes, signature, short-lived artifact URLs) |
| `sessions.verifyEvidenceOnServer(id)` | `GET /sessions/:id/evidence/verify` |
| `sessions.submitCapture(id, captureToken, { video, telemetry })` | `POST /sessions/:id/captures` — custom capture with your own camera |
| `evidence.keys()` | `GET /evidence-keys` |
| `evidence.verify(id)` | Fetches the envelope and the keys and verifies the Ed25519 signature **locally** |
| `verifyEvidenceSignature({ sessionId, attempt, bundleHash, signature }, keys)` | Pure function, no network |
| `verifyWebhook` / `constructEvent` / `checkWebhook` | See below |

Session flows: `ONBOARDING` (with a document reference), `AUTHENTICATION` (with an enrolled template), `ENROLLMENT`, `LIVENESS_ONLY`. All envelope, decision, check and reason types are exported (`SessionEnvelope`, `Decision`, `Check`, `Reason`, `SessionStatus`...).

## Webhooks

Deliveries come from the Catalisa Webhooks Engine and are signed with **RSA-SHA256 (PKCS#1 v1.5)** — an asymmetric signature. You verify with the subscription's **public key**; there is no shared secret.

| Header | |
|---|---|
| `x-webhook-id` | Id of this attempt (changes on every retry) |
| `x-webhook-timestamp` | ISO 8601 |
| `x-webhook-key-id` | Which key signed — select the public key by this value |
| `x-webhook-signature` | `v1=` + base64 signature over `x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body` |

Get the public keys with `GET /webhooks-engine/api/v1/subscriptions/:id/keys` (`attributes.keyId`, `attributes.publicKey`) and keep a map `keyId → PEM` (keep both keys during a rotation).

```ts
import express from 'express'
import { constructEvent, WebhookVerificationError } from '@catalisa/biometrics'

const publicKeys = JSON.parse(process.env.CATALISA_WEBHOOK_KEYS!) // { "whk_…": "-----BEGIN PUBLIC KEY-----…" }

app.post('/webhooks/biometrics', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const event = constructEvent(req.body, req.headers, publicKeys) // req.body is a Buffer
    if (event.type === 'biometrics.session.completed') {
      // event.data: { sessionId, outcome, reasons, flow, customerId, subaccountId?, ... }
    }
    res.sendStatus(200)
  } catch (e) {
    if (e instanceof WebhookVerificationError) return res.status(400).send(e.code)
    throw e
  }
})
```

Security checklist:

- **Use the raw body.** Parsing and re-serializing the JSON changes the bytes and breaks the signature (`express.raw`, not `express.json`, on this route).
- **Timestamp tolerance** defaults to 300 s (`{ toleranceSeconds }`). The server does not reject old deliveries; you do.
- **Idempotency** by the body's `id` (stable across retries), never by `x-webhook-id`.
- `verifyWebhook(...)` returns a boolean; `checkWebhook(...)` returns the failure reason (`MISSING_HEADERS`, `TIMESTAMP_INVALID`, `TIMESTAMP_OUT_OF_TOLERANCE`, `UNKNOWN_KEY_ID`, `UNSUPPORTED_SIGNATURE_VERSION`, `INVALID_SIGNATURE`).

Events: `biometrics.session.created`, `.completed`, `.review_required`, `.expired`, `biometrics.subject.locked`, `biometrics.subject.erased`, `biometrics.enrollment.created`, `.revoked`, `biometrics.usage.recorded`.

## Signed evidence

Every evaluated session carries evidence signed with the organization's Ed25519 key. The signed message is `${sessionId}|${attempt}|${bundleHash}|${signedAt}`.

```ts
const result = await bio.evidence.verify(sessionId)
// { valid: true, keyId: 'ev-…', unknownKey: false, retiredAt: null }
```

Retired keys stay published, so old evidence remains verifiable.

## Errors

Every API error is a `BiometricsError` with `status`, `code` (the specific `details.code` when present, otherwise `error`), `requestId`, `details` and the raw `body`.

| Class | When |
|---|---|
| `AuthenticationError` | 401 — missing, invalid, revoked or expired key |
| `QuotaExceededError` | 402 `QUOTA_EXCEEDED` — the subaccount's monthly quota is used up (`details.monthlyQuota`, `details.used`, `details.periodEnd`) |
| `SubaccountSuspendedError` | 403 `SUBACCOUNT_SUSPENDED` |
| `PermissionError` | Other 403 — missing permission, subject locked |
| `ValidationError` | 400 / 413 / 415 / 422 |
| `NotFoundError` | 404 |
| `RateLimitError` | 429, with `retryAfter` (seconds) |
| `ServerError` | 5xx (503 = engine unavailable) |
| `ConnectionError` | No response: `code` is `TIMEOUT` or `CONNECTION` |
| `WebhookVerificationError` | Webhook not authentic |

```ts
try {
  await bio.sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abertura de conta' })
} catch (e) {
  if (e instanceof QuotaExceededError) { /* 402 */ }
  else if (e instanceof SubaccountSuspendedError) { /* 403 */ }
  else throw e
}
```

## Retries

- **429** is retried for every method, honoring `Retry-After` — the rate limiter rejects before the handler runs, so nothing was done.
- **5xx and network errors** are retried only for reads (`get`, `list`, `evidence`, `evidence.keys`), with exponential backoff and jitter.
- **Session creation is never retried on 5xx/network errors**: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and consume quota twice). `idempotencyKey` is still forwarded for forward compatibility.

## Subaccounts

With an organization key, pass `subaccountId` to act on behalf of a subaccount; with a subaccount key, requests are bound to it automatically. Envelopes and webhook payloads carry `subaccountId` (`null` for organization sessions) when the server supports subaccounts.

## License

MIT
