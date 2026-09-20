# catalisa-biometrics

Ruby SDK for **Catalisa Biometrics** — liveness and face-match sessions, signed evidence and webhook verification.

- Standard library only: `net/http`, `openssl`, `json`. Ruby **3.0+**
- One typed error carrying the API's own code
- Offline verification of the Ed25519 evidence signature

```bash
gem install catalisa-biometrics
```

## How the flow works

1. **Your server** creates a session and receives `handoff.captureUrl`.
2. The person opens that URL (browser tab, iframe or WebView) and does the challenge.
3. The decision arrives **on your server** through the `biometrics.session.completed` webhook, or through `#session`.

The capture page never reveals the result to the person in front of the camera — on purpose, so it cannot be used as a fraud oracle. Never decide anything from front-end events.

## Quick start

```ruby
require "catalisa/biometrics"

client = Catalisa::Biometrics::Client.new(api_key: ENV.fetch("CATALISA_API_KEY"))

session = client.create_session(
  flow: Catalisa::Biometrics::Flows::LIVENESS_ONLY,
  purpose: "abertura de conta",
  metadata: { orderId: "123" },
)
# send the person to session.dig("handoff", "captureUrl")

envelope = client.session(session["sessionId"])
# proceed when envelope["status"] == "APPROVED"
```

## API

| Method | What it does |
|---|---|
| `create_session` | Opens a session; the envelope comes with `handoff` |
| `session` | Reads the session, with decision, checks and evidence |
| `sessions` | Lists sessions, newest first, with filters and pagination |
| `cancel_session` | Closes a session that has not settled; the allowance slot comes back |
| `evidence` | Signed evidence plus short-lived download links |
| `verify_evidence_on_server` | Asks the API to check the signature |
| `evidence_keys` | Published signing keys, retired ones included |
| `Evidence.verify` | Checks the signature **offline**, without calling Catalisa |
| `submit_capture` | Uploads a capture recorded by your own app |
| `WebhookVerifier#verify` | Verifies a delivery and returns the parsed event |

## Errors

Every failure raises `Catalisa::Biometrics::Error` with the API's own code:

```ruby
begin
  session = client.create_session(flow: "LIVENESS_ONLY", purpose: "kyc")
rescue Catalisa::Biometrics::Error => e
  if e.quota_exceeded?
    # the customer's monthly allowance is gone (402); e.details has the numbers
  elsif e.subaccount_suspended?
    # suspended: nothing opens until it is reactivated
  elsif e.transient?
    # rate limit, server fault or network: worth trying again
  end
  warn "#{e.code}: #{e.message} (request #{e.request_id})"
end
```

## Retries

- **429** is retried for every method, honoring `Retry-After`: the rate limiter refuses before anything runs.
- **5xx and network failures** are retried only for reads.
- **Session creation is never retried** on those: the server does not deduplicate by `Idempotency-Key` yet, and a retry could open two sessions (and spend the allowance twice).

## Webhooks

The delivery is signed with the subscription's **private** key; you verify with the public one. Verify the **raw** bytes — parsing and re-serializing the JSON changes them and the signature will not match.

```ruby
verifier = Catalisa::Biometrics::WebhookVerifier.new(public_keys_by_key_id)

post "/webhooks/biometrics" do
  raw = request.body.read
  begin
    event = verifier.verify(request.env, raw)
  rescue Catalisa::Biometrics::WebhookVerificationError
    halt 400
  end
  # event["id"] is stable: use it for idempotency, a delivery can repeat
  status 200 # answer fast; do the work afterwards
end
```

It reads headers in whatever shape your stack hands them over, Rack's `HTTP_X_WEBHOOK_ID` included. The engine does not refuse old deliveries — the receiver does, with a five-minute tolerance by default.

## Signed evidence

```ruby
keys = client.evidence_keys
evidence = client.evidence(session_id)
out = Catalisa::Biometrics::Evidence.verify(session_id, envelope["attempt"], evidence["bundleHash"], evidence["signature"], keys)
# out[:valid] says whether this is the bundle Catalisa signed
```

The message is `sessionId|attempt|bundleHash|signedAt`, signed with Ed25519. Retired keys stay published, so evidence signed years ago still verifies.

## Test environment

An API key belongs to one world and says so on every session it opens:

| | `test` (sandbox) | `live` |
|---|---|---|
| Engine | Simulated, deterministic | The real one configured for the account |
| Result | Decided by the CPF ending in `subject_ref` | Decided by the engine |
| Allowance | Not spent | Spent |
| Billing | Never billed | Billed |
| Visibility | A test key only reads test sessions; a live key only reads live ones | |

A test key needs no engine configured, so you can integrate on day one. The envelope and the `session.completed` payload carry `environment`.

Endings that drive the sandbox result: `…-25` (or any other) approves, `…-11` comes back inconclusive for human review, `…-55` asks for a second attempt and then approves, `…-66` fails as an engine error, `…-00`, `…-33` and `…-44` reject by face match, liveness and continuity.

## Subaccounts

With an organization key, pass `subaccount_id:` to act on behalf of a subaccount; with a subaccount key the scope is already bound. Envelopes and webhook payloads carry `subaccountId` (`nil` for organization sessions).

## Custom capture

`submit_capture` uploads a video your own app recorded, authenticating with the session's `captureToken` — the account key never leaves your server. Only `video/webm` and `video/mp4` are accepted, up to 16 MiB and 24 seconds.

Prefer the hosted page when you can: it already runs the quality checks that keep a useless recording from spending an attempt.

## Development

```bash
ruby -Ilib -Itest -e 'Dir.glob("test/*_test.rb").each { |f| require File.expand_path(f) }'
```

The tests share `vectors/vectors.json` with the Node, Python, Go, PHP and .NET SDKs — the same signatures, produced by the building block's own code.

Releases go out through GitHub Actions with RubyGems trusted publishing: no API key is stored anywhere.

## License

MIT
