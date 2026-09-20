# Catalisa.Biometrics

.NET SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- .NET 8 and .NET Standard 2.1
- One dependency, BouncyCastle, only because .NET has no Ed25519 and the receipt is signed with it
- Typed exception carrying the API's own error code

```bash
dotnet add package Catalisa.Biometrics
```

## How the flow works

1. **Your server** creates a session and receives `Handoff.CaptureUrl`.
2. The person opens that URL (browser tab, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or through `GetSessionAsync`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything from front-end events.

## Quick start

```csharp
using Catalisa.Biometrics;

using var client = new BiometricsClient(Environment.GetEnvironmentVariable("CATALISA_API_KEY")!);

var session = await client.CreateSessionAsync(new CreateSessionInput
{
    Flow = Flows.LivenessOnly,
    Purpose = "abertura de conta",
    Metadata = new Dictionary<string, string> { ["orderId"] = "123" },
});
// send the person to session.Handoff!.CaptureUrl

var envelope = await client.GetSessionAsync(session.SessionId);
if (envelope.Status == SessionStatuses.Approved)
{
    // proceed
}
```

## API

| Member | What it does |
|---|---|
| `CreateSessionAsync` | Opens a session; the envelope comes with `Handoff` |
| `GetSessionAsync` | Reads the session, with decision, checks and evidence |
| `ListSessionsAsync` | Lists sessions, newest first, with filters and pagination |
| `CancelSessionAsync` | Closes a session that has not settled; the allowance slot comes back |
| `GetEvidenceAsync` | Signed evidence plus short-lived download links |
| `GetEvidenceKeysAsync` | Published signing keys, retired ones included |
| `Evidence.Verify` | Checks the signature **offline**, without calling Catalisa |
| `SubmitCaptureAsync` | Uploads a capture recorded by your own app |
| `WebhookVerifier.Verify` | Verifies a delivery and returns the parsed event |

## Errors

Every failure throws `BiometricsException` with the API's own code:

```csharp
try
{
    var session = await client.CreateSessionAsync(input);
}
catch (BiometricsException e) when (e.IsQuotaExceeded)
{
    // the customer's monthly allowance is gone (402); e.Details has the numbers
}
catch (BiometricsException e) when (e.IsSubaccountSuspended)
{
    // suspended: nothing opens until it is reactivated
}
catch (BiometricsException e) when (e.IsTransient)
{
    // rate limit, server fault or network: worth trying again
}
```

## Retries

- **429** is retried for every method, honoring `Retry-After`: the rate limiter refuses before anything runs.
- **5xx and network failures** are retried only for reads.
- **Session creation is never retried** on those: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and spend the allowance twice).

## Webhooks

The delivery is signed with the subscription's **private** key; you verify with the public one. Verify the **raw** bytes — model binding that re-serializes the JSON changes them and the signature will not match.

```csharp
var verifier = new WebhookVerifier(publicKeysByKeyId);

app.MapPost("/webhooks/biometrics", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var raw = await reader.ReadToEndAsync();
    try
    {
        var evt = verifier.Verify(name => request.Headers[name].FirstOrDefault(), raw);
        // evt.Id is stable: use it for idempotency, a delivery can repeat
        return Results.Ok();   // answer fast; do the work afterwards
    }
    catch (WebhookVerificationException)
    {
        return Results.BadRequest();
    }
});
```

The engine does not refuse old deliveries — the receiver does, with a five-minute tolerance by default.

## Signed evidence

```csharp
var keys = await client.GetEvidenceKeysAsync();
var evidence = await client.GetEvidenceAsync(sessionId);
var result = Evidence.Verify(sessionId, envelope.Attempt, evidence.BundleHash, evidence.Signature!, keys);
// result.Valid says whether this is the bundle Catalisa signed
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

A test key needs no engine configured, so you can integrate on day one. `Session.IsSandbox` tells a rehearsal from the real thing.

Endings that drive the sandbox result: `…-25` (or any other) approves, `…-11` comes back inconclusive for human review, `…-55` asks for a second attempt and then approves, `…-66` fails as an engine error, `…-00`, `…-33` and `…-44` reject by face match, liveness and continuity.

## Subaccounts

With an organization key, set `BiometricsOptions.SubaccountId` to act on behalf of a subaccount; with a subaccount key the scope is already bound. Envelopes and webhook payloads carry `subaccountId` (`null` for organization sessions).

## Custom capture

`SubmitCaptureAsync` uploads a video your own app recorded, authenticating with the session's `CaptureToken` — the account key never leaves your server. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24 seconds.

Prefer the hosted page when you can: it already runs the quality checks that keep a useless recording from spending an attempt.

## Development

```bash
dotnet test tests/Catalisa.Biometrics.Tests.csproj
```

The tests share `vectors/vectors.json` with the Node, Python, Go and PHP SDKs — the same signatures, produced by the building block's own code.

Releases go out through GitHub Actions with NuGet trusted publishing: no API key is stored anywhere. Tag `packages/dotnet/vX.Y.Z` and the workflow tests, packs and pushes.

## License

MIT
