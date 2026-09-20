# catalisa/biometrics

PHP SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- No Composer dependencies: `ext-curl`, `ext-json`, `ext-openssl` and `ext-sodium`, all standard. PHP **8.1+**
- Typed exception carrying the API's own error code
- Offline verification of the Ed25519 evidence signature

```bash
composer require catalisa/biometrics
```

## How the flow works

1. **Your server** creates a session and receives `handoff.captureUrl`.
2. The person opens that URL (browser tab, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or through `getSession()`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything from front-end events.

## Quick start

```php
use Catalisa\Biometrics\Client;

$client = new Client(apiKey: getenv('CATALISA_API_KEY'));

$session = $client->createSession([
    'flow' => 'LIVENESS_ONLY',
    'purpose' => 'abertura de conta',
    'metadata' => ['orderId' => '123'],
]);
// send the person to $session['handoff']['captureUrl']

$envelope = $client->getSession($session['sessionId']);
if ($envelope['status'] === 'APPROVED') {
    // proceed
}
```

## API

| Method | What it does |
|---|---|
| `createSession` | Opens a session; the answer comes with `handoff` |
| `getSession` | Reads the session, with decision, checks and evidence |
| `listSessions` | Lists sessions, newest first, with filters and pagination |
| `cancelSession` | Closes a session that has not settled; the allowance slot comes back |
| `sessionEvidence` | Signed evidence plus short-lived download links |
| `verifyEvidenceOnServer` | Asks the API to check the signature |
| `evidenceKeys` | Published signing keys, retired ones included |
| `Evidence::verify` | Checks the signature **offline**, without calling Catalisa |
| `submitCapture` | Uploads a capture recorded by your own app |
| `WebhookVerifier::verify` | Verifies a delivery and returns the parsed event |

## Errors

Every failure throws `BiometricsException` with the API's own code:

```php
use Catalisa\Biometrics\BiometricsException;

try {
    $session = $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'kyc']);
} catch (BiometricsException $e) {
    if ($e->isQuotaExceeded()) {
        // the customer's monthly allowance is gone (402); $e->details has the numbers
    } elseif ($e->isSubaccountSuspended()) {
        // suspended: nothing opens until it is reactivated
    } elseif ($e->isTransient()) {
        // rate limit, server fault or network: worth trying again
    }
    error_log("{$e->errorCode}: {$e->getMessage()} (request {$e->requestId})");
}
```

## Retries

- **429** is retried for every method, honoring `Retry-After`: the rate limiter refuses before anything runs.
- **5xx and network failures** are retried only for reads.
- **Session creation is never retried** on those: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and spend the allowance twice). The key is still forwarded for forward compatibility.

## Webhooks

The delivery is signed with the subscription's **private** key; you verify with the public one. Verify the **raw** bytes — decoding and re-encoding the JSON changes them and the signature will not match.

```php
use Catalisa\Biometrics\WebhookVerifier;
use Catalisa\Biometrics\WebhookVerificationException;

$verifier = new WebhookVerifier(json_decode(getenv('CATALISA_WEBHOOK_KEYS'), true));

try {
    $event = $verifier->verify($_SERVER, file_get_contents('php://input'));
} catch (WebhookVerificationException $e) {
    http_response_code(400);
    exit('invalid signature');
}
// $event['id'] is stable: use it for idempotency, a delivery can repeat
http_response_code(200); // answer fast; do the work afterwards
```

It reads headers in whatever shape your stack hands them over: `$_SERVER`'s `HTTP_X_WEBHOOK_ID`, a framework's `x-webhook-id`, arrays included. The engine does not refuse old deliveries — the receiver does, with a 5-minute tolerance by default.

## Signed evidence

```php
use Catalisa\Biometrics\Evidence;

$keys = $client->evidenceKeys();
$evidence = $client->sessionEvidence($sessionId);
$out = Evidence::verify($sessionId, $envelope['attempt'], $evidence['bundleHash'], $evidence['signature'], $keys);
// $out['valid'] says whether this is the bundle Catalisa signed
```

The message is `sessionId|attempt|bundleHash|signedAt`, signed with Ed25519. Retired keys stay published, so evidence signed years ago still verifies.

## Test environment

An API key belongs to one world and says so on every session it opens:

| | `test` (sandbox) | `live` |
|---|---|---|
| Engine | Simulated, deterministic | The real one configured for the account |
| Result | Decided by the CPF ending in `subjectRef` | Decided by the engine |
| Allowance | Not spent | Spent |
| Billing | Never billed | Billed |
| Visibility | A test key only reads test sessions; a live key only reads live ones | |

A test key needs no engine configured, so you can integrate on day one. The envelope and the `session.completed` payload carry `environment`, which is how a handler tells a rehearsal from the real thing.

Endings that drive the sandbox result: `…-25` (or any other) approves, `…-11` comes back inconclusive for human review, `…-55` asks for a second attempt and then approves, `…-66` fails as an engine error, `…-00`, `…-33` and `…-44` reject by face match, liveness and continuity.

## Subaccounts

With an organization key, pass `subaccountId:` to the constructor to act on behalf of a subaccount; with a subaccount key the scope is already bound. Envelopes and webhook payloads carry `subaccountId` (`null` for organization sessions).

## Custom capture

`submitCapture` uploads a video your own app recorded, authenticating with the session's `captureToken` — the account key never leaves your server. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24 seconds.

Prefer the hosted page when you can: it already runs the quality checks that keep a useless recording from spending an attempt.

## Development

```bash
composer install
composer test
```

The tests share `vectors/vectors.json` with the Node, Python and Go SDKs — the same signatures, produced by the building block's own code.

## License

MIT
