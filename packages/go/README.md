# catalisa-biometrics-sdk/packages/go

Go SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- Standard library only, no dependencies, Go **1.21+**
- Typed errors you can branch on with `errors.Is`
- Offline verification of the Ed25519 evidence signature

```bash
go get github.com/catalisaio/catalisa-biometrics-sdk/packages/go@latest
```

```go
import biometrics "github.com/catalisaio/catalisa-biometrics-sdk/packages/go"
```

## How the flow works

1. **Your server** creates a session and receives `Handoff.CaptureURL`.
2. The person opens that URL (browser tab, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or through `GetSession`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything from front-end events.

## Quick start

```go
client, err := biometrics.New(biometrics.Options{APIKey: os.Getenv("CATALISA_API_KEY")})
if err != nil {
    log.Fatal(err)
}

session, err := client.CreateSession(ctx, biometrics.CreateSessionInput{
    Flow:     biometrics.FlowLivenessOnly,
    Purpose:  "abertura de conta",
    Metadata: map[string]string{"orderId": "123"},
})
if err != nil {
    log.Fatal(err)
}
// send the person to session.Handoff.CaptureURL

envelope, err := client.GetSession(ctx, session.SessionID)
if err == nil && envelope.Status == biometrics.StatusApproved {
    // proceed
}
```

## API

| Method | What it does |
|---|---|
| `CreateSession` | Opens a session; the envelope comes with `Handoff` |
| `GetSession` | Reads the session, with decision, checks and evidence |
| `ListSessions` | Lists sessions, newest first, with filters and pagination |
| `CancelSession` | Closes a session that has not settled; the allowance slot comes back |
| `SessionEvidence` | Signed evidence plus short-lived download links |
| `VerifyEvidenceOnServer` | Asks the API to check the signature |
| `EvidenceKeys` | Published signing keys, retired ones included |
| `VerifyEvidence` | Checks the signature **offline**, without calling Catalisa |
| `SubmitCapture` | Uploads a capture recorded by your own app |
| `WebhookVerifier.Verify` | Verifies a delivery and parses the event |

## Errors

Every failure is an `*Error` carrying the API's own `Code`. Branch on the sentinels:

```go
_, err := client.CreateSession(ctx, in)
switch {
case errors.Is(err, biometrics.ErrQuotaExceeded):
    // the customer's monthly allowance is gone (402)
case errors.Is(err, biometrics.ErrPermissionDenied):
    var apiErr *biometrics.Error
    if errors.As(err, &apiErr) && apiErr.Code == "SUBACCOUNT_SUSPENDED" {
        // subaccount suspended: nothing opens until it is reactivated
    }
case errors.Is(err, biometrics.ErrNotFound):
    // no session with that id in this scope
}
```

`ErrAuthentication`, `ErrInvalidRequest`, `ErrRateLimit`, `ErrServer` and `ErrConnection` complete the set. `Error.Details` keeps whatever the API attached — the quota numbers, the offending fields.

## Retries

- **429** is retried for every method, honoring `Retry-After`: the rate limiter refuses before anything runs.
- **5xx and network failures** are retried only for reads.
- **Session creation is never retried** on those: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and spend the allowance twice). `IdempotencyKey` is still forwarded for forward compatibility.

## Webhooks

The delivery is signed with the subscription's **private** key; you verify with the public one. Verify the **raw** bytes — decoding and re-encoding the JSON changes them and the signature will not match.

```go
verifier := biometrics.NewWebhookVerifier(map[string]string{keyID: publicKeyPEM})

func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    event, err := verifier.Verify(r.Header, body)
    if err != nil {
        http.Error(w, "invalid signature", http.StatusBadRequest)
        return
    }
    // event.ID is stable: use it for idempotency, a delivery can repeat
    w.WriteHeader(http.StatusOK) // answer fast; do the work afterwards
}
```

The engine does not refuse old deliveries — the receiver does. The default tolerance is 5 minutes.

## Signed evidence

```go
keys, _ := client.EvidenceKeys(ctx)
ev, _ := client.SessionEvidence(ctx, sessionID)
out := biometrics.VerifyEvidence(sessionID, envelope.Attempt, ev.BundleHash, *ev.Signature, keys)
// out.Valid says whether this is the bundle Catalisa signed
```

The message is `sessionId|attempt|bundleHash|signedAt`, signed with Ed25519. Retired keys stay published, so evidence signed years ago still verifies.

## Test environment

An API key belongs to one world and says so on every session it opens:

| | `test` (sandbox) | `live` |
|---|---|---|
| Engine | Simulated, deterministic | The real one configured for the account |
| Result | Decided by the CPF ending in `SubjectRef` | Decided by the engine |
| Allowance | Not spent | Spent |
| Billing | Never billed | Billed |
| Visibility | A test key only reads test sessions; a live key only reads live ones | |

A test key needs no engine configured, so you can integrate on day one. `Session.IsSandbox()` tells a rehearsal from the real thing, and so does `environment` in the `session.completed` payload.

Endings that drive the sandbox result: `…-25` (or any other) approves, `…-11` comes back inconclusive for human review, `…-55` asks for a second attempt and then approves, `…-66` fails as an engine error, `…-00`, `…-33` and `…-44` reject by face match, liveness and continuity.

## Subaccounts

With an organization key, set `Options.SubaccountID` to act on behalf of a subaccount; with a subaccount key the scope is already bound. Envelopes and webhook payloads carry `subaccountId` (`nil` for organization sessions).

## Custom capture

`SubmitCapture` uploads a video your own app recorded, authenticating with the session's `CaptureToken` — the account key never leaves your server. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24 seconds.

Prefer the hosted page when you can: it already does the quality checks that keep a useless recording from spending an attempt.

## Development

The module lives in a monorepo with the other SDKs. Tests run with the standard toolchain:

```bash
cd packages/go && go test ./...
```

They share `vectors/vectors.json` with the Node and Python SDKs — the same signatures, produced by the building block's own code.

Releases are tagged `packages/go/vX.Y.Z`, which is how Go modules version a package inside a monorepo.

## License

MIT
