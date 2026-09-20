# io.github.catalisaio:catalisa-biometrics

Java SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- Java **17+**; works from Kotlin, Scala and anything else on the JVM
- One dependency, Jackson: the JDK brings HTTP, RSA and Ed25519, but no JSON parser
- Typed exception carrying the API's own error code

```xml
<dependency>
  <groupId>io.github.catalisaio</groupId>
  <artifactId>catalisa-biometrics</artifactId>
  <version>0.1.0</version>
</dependency>
```

```kotlin
// Gradle
implementation("io.github.catalisaio:catalisa-biometrics:0.1.0")
```

## How the flow works

1. **Your server** creates a session and receives `handoff.captureUrl`.
2. The person opens that URL (browser tab, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or through `getSession`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything from front-end events.

## Quick start

```java
var client = BiometricsClient.of(System.getenv("CATALISA_API_KEY"));

var session = client.createSession(Map.of(
    "flow", Models.Flows.LIVENESS_ONLY,
    "purpose", "abertura de conta",
    "metadata", Map.of("orderId", "123")));
// send the person to session.handoff().captureUrl()

var envelope = client.getSession(session.sessionId());
if (Models.Statuses.APPROVED.equals(envelope.status())) {
    // proceed
}
```

From Kotlin, the same artifact:

```kotlin
val client = BiometricsClient.of(System.getenv("CATALISA_API_KEY"))
val session = client.createSession(mapOf("flow" to "LIVENESS_ONLY", "purpose" to "abertura de conta"))
```

## API

| Method | What it does |
|---|---|
| `createSession` | Opens a session; the envelope comes with `handoff` |
| `getSession` | Reads the session, with decision, checks and evidence |
| `listSessions` | Lists sessions, newest first, with filters and pagination |
| `cancelSession` | Closes a session that has not settled; the allowance slot comes back |
| `getEvidence` | Signed evidence plus short-lived download links |
| `getEvidenceKeys` | Published signing keys, retired ones included |
| `Evidence.verify` | Checks the signature **offline**, without calling Catalisa |
| `submitCapture` | Uploads a capture recorded by your own app |
| `WebhookVerifier.verify` | Verifies a delivery and returns the parsed event |

## Errors

Every failure throws `BiometricsException` with the API's own code:

```java
try {
    var session = client.createSession(input);
} catch (BiometricsException e) {
    if (e.isQuotaExceeded()) {
        // the customer's monthly allowance is gone (402); e.details() has the numbers
    } else if (e.isSubaccountSuspended()) {
        // suspended: nothing opens until it is reactivated
    } else if (e.isTransient()) {
        // rate limit, server fault or network: worth trying again
    }
}
```

## Retries

- **429** is retried for every method, honoring `Retry-After`: the rate limiter refuses before anything runs.
- **5xx and network failures** are retried only for reads.
- **Session creation is never retried** on those: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and spend the allowance twice).

## Webhooks

The delivery is signed with the subscription's **private** key; you verify with the public one. Verify the **raw** bytes — binding the request to a model and re-serializing it changes them, and the signature will not match.

```java
var verifier = new WebhookVerifier(publicKeysByKeyId);

@PostMapping("/webhooks/biometrics")
ResponseEntity<Void> receive(@RequestBody String rawBody, @RequestHeader HttpHeaders headers) {
    try {
        var event = verifier.verify(headers::getFirst, rawBody);
        // event.id() is stable: use it for idempotency, a delivery can repeat
        return ResponseEntity.ok().build(); // answer fast; do the work afterwards
    } catch (WebhookVerifier.VerificationException e) {
        return ResponseEntity.badRequest().build();
    }
}
```

The engine does not refuse old deliveries — the receiver does, with a five-minute tolerance by default.

## Signed evidence

```java
var keys = client.getEvidenceKeys();
var evidence = client.getEvidence(sessionId);
var result = Evidence.verify(sessionId, envelope.attempt(), evidence.bundleHash(), evidence.signature(), keys);
// result.valid() says whether this is the bundle Catalisa signed
```

The message is `sessionId|attempt|bundleHash|signedAt`, signed with Ed25519 — which the JDK has had since 15, so nothing beyond it is needed. Retired keys stay published, so evidence signed years ago still verifies.

## Test environment

An API key belongs to one world and says so on every session it opens:

| | `test` (sandbox) | `live` |
|---|---|---|
| Engine | Simulated, deterministic | The real one configured for the account |
| Result | Decided by the CPF ending in `subjectRef` | Decided by the engine |
| Allowance | Not spent | Spent |
| Billing | Never billed | Billed |
| Visibility | A test key only reads test sessions; a live key only reads live ones | |

A test key needs no engine configured, so you can integrate on day one. `session.isSandbox()` tells a rehearsal from the real thing.

Endings that drive the sandbox result: `…-25` (or any other) approves, `…-11` comes back inconclusive for human review, `…-55` asks for a second attempt and then approves, `…-66` fails as an engine error, `…-00`, `…-33` and `…-44` reject by face match, liveness and continuity.

## Subaccounts

With an organization key, set `subaccountId` on the builder to act on behalf of a subaccount; with a subaccount key the scope is already bound. Envelopes and webhook payloads carry `subaccountId` (`null` for organization sessions).

## Custom capture

`submitCapture` uploads a video your own app recorded, authenticating with the session's capture token — the account key never leaves your server. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24 seconds.

Prefer the hosted page when you can: it already runs the quality checks that keep a useless recording from spending an attempt.

## Development

```bash
mvn test
```

The tests read `vectors/vectors.json` from the repository root — the same signatures the Node, Python, Go, PHP, .NET and Ruby SDKs verify.

Releases go out through GitHub Actions: the artifact is signed with GPG and published to Maven Central through the Sonatype portal.

## License

MIT
