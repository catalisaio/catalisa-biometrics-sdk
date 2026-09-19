# Example: Node server + web modal

A single file server (`node:http`, no framework) that shows the whole integration:

1. `POST /api/biometrics/session` creates the session **on the server** with `@catalisa/biometrics` and returns only the `captureUrl`.
2. The page opens the capture in a modal with `@catalisa/biometrics-web`.
3. `POST /webhooks/biometrics` verifies the RSA-SHA256 signature, deduplicates by event `id` and stores the decision.
4. After the `done` event the page polls `GET /api/biometrics/result`, which says only whether it finished — scores and reasons stay on the server.

```bash
npm install            # at the repository root (workspaces)
npm run build
CATALISA_API_KEY=… \
CATALISA_WEBHOOK_KEYS='{"whk_…":"-----BEGIN PUBLIC KEY-----\n…"}' \
node examples/node-server/server.mjs
```

For the modal to render, the page's origin must be in the provider's `allowedEmbedHosts`. Point your webhook subscription (filter `biometrics.*`) at `https://<your-host>/webhooks/biometrics`.
