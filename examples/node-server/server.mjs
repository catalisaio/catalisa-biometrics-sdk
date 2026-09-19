// End-to-end example (Node 18+, no framework): serves a page, creates sessions and receives the webhook.
//
//   CATALISA_API_KEY=…  CATALISA_WEBHOOK_KEYS='{"whk_…":"-----BEGIN PUBLIC KEY-----…"}'  node server.mjs
//
//   GET  /                         page with the "Verify identity" button (modal via @catalisa/biometrics-web)
//   POST /api/biometrics/session   creates the session on the server and returns ONLY the captureUrl
//   POST /webhooks/biometrics      verifies the signature and records the decision
//   GET  /api/biometrics/result    what the page polls after `done` (the decision stays on the server)
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { Biometrics, BiometricsError, QuotaExceededError, SubaccountSuspendedError, constructEvent, WebhookVerificationError } from '@catalisa/biometrics'

const bio = new Biometrics({ apiKey: process.env.CATALISA_API_KEY, baseUrl: process.env.CATALISA_BIOMETRICS_URL })
const publicKeys = JSON.parse(process.env.CATALISA_WEBHOOK_KEYS ?? '{}')
const page = readFileSync(new URL('./public/index.html', import.meta.url))
const umd = readFileSync(new URL('../../packages/web/dist/biometrics-web.umd.js', import.meta.url)) // or load it from the CDN

// In a real app: your database, keyed by sessionId and by event id (idempotency).
const decisions = new Map()
const processedEvents = new Set()

const readBody = (req) => new Promise((resolve) => {
  const chunks = []
  req.on('data', (c) => chunks.push(c))
  req.on('end', () => resolve(Buffer.concat(chunks)))
})
const json = (res, status, body) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')
  if (req.method === 'GET' && url.pathname === '/') return res.writeHead(200, { 'content-type': 'text/html' }).end(page)
  if (req.method === 'GET' && url.pathname === '/biometrics-web.umd.js') return res.writeHead(200, { 'content-type': 'text/javascript' }).end(umd)

  if (req.method === 'POST' && url.pathname === '/api/biometrics/session') {
    try {
      const session = await bio.sessions.create({
        flow: 'LIVENESS_ONLY',
        purpose: 'abertura de conta',
        appearance: { redirectUrl: process.env.REDIRECT_URL }, // optional: where the page goes when finished
      })
      decisions.set(session.sessionId, { status: session.status })
      return json(res, 201, { sessionId: session.sessionId, captureUrl: session.handoff.captureUrl })
    } catch (e) {
      if (e instanceof QuotaExceededError) return json(res, 402, { error: 'quota_exceeded' })
      if (e instanceof SubaccountSuspendedError) return json(res, 403, { error: 'account_suspended' })
      if (e instanceof BiometricsError) return json(res, 502, { error: e.code })
      throw e
    }
  }

  if (req.method === 'POST' && url.pathname === '/webhooks/biometrics') {
    const rawBody = await readBody(req)
    let event
    try {
      event = constructEvent(rawBody, req.headers, publicKeys)
    } catch (e) {
      if (e instanceof WebhookVerificationError) return json(res, 400, { error: e.code })
      throw e
    }
    if (!processedEvents.has(event.id)) {
      processedEvents.add(event.id)
      if (event.type === 'biometrics.session.completed') {
        decisions.set(event.data.sessionId, { status: event.data.outcome, reasons: event.data.reasons })
      }
    }
    return json(res, 200, { received: true })
  }

  if (req.method === 'GET' && url.pathname === '/api/biometrics/result') {
    // Tell the person only what YOUR product wants them to know, never scores or reasons.
    const decision = decisions.get(url.searchParams.get('sessionId') ?? '')
    if (!decision) return json(res, 404, { error: 'not_found' })
    return json(res, 200, { finished: ['APPROVED', 'REJECTED', 'INCONCLUSIVE'].includes(decision.status) })
  }

  res.writeHead(404).end()
}).listen(Number(process.env.PORT ?? 3000), () => console.log(`example at http://localhost:${process.env.PORT ?? 3000}`))
