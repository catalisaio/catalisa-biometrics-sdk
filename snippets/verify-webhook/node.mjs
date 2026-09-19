// Minimal server (node:http only) that receives the Biometrics webhook and verifies the signature.
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"} (GET /webhooks-engine/api/v1/subscriptions/:id/keys)
import { createServer } from 'node:http'
import { constructEvent, WebhookVerificationError } from '@catalisa/biometrics'

const publicKeys = JSON.parse(process.env.CATALISA_WEBHOOK_KEYS)

createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/webhooks/biometrics') return res.writeHead(404).end()
  const chunks = []
  req.on('data', (chunk) => chunks.push(chunk))
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks) // RAW body: do not JSON.parse before verifying
    try {
      const event = constructEvent(rawBody, req.headers, publicKeys) // default tolerance: 300 s
      // Idempotency: use event.id (stable across retries), not the x-webhook-id header.
      if (event.type === 'biometrics.session.completed') {
        console.log('session', event.data.sessionId, '→', event.data.outcome)
      }
      res.writeHead(200).end('ok')
    } catch (e) {
      if (!(e instanceof WebhookVerificationError)) throw e
      console.warn('webhook rejected:', e.code)
      res.writeHead(400).end(e.code)
    }
  })
}).listen(Number(process.env.PORT ?? 3000))
