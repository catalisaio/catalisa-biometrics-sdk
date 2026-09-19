// HTTP mock of Catalisa Biometrics, faithful to the server contract (origin/main + subaccounts contract).
// Used to execute the server snippets without credentials. Shapes copied from:
//  - src/biometrics/routes/sessions.router.ts (routes, { data }, list with meta.total/page)
//  - src/shared/utils/result-handler.ts ({ error, message, details })
//  - src/shared/errors (MissingAuthorizationError → details.code MISSING_AUTHORIZATION)
//  - the subaccounts contract (402 PAYMENT_REQUIRED/QUOTA_EXCEEDED, 403 FORBIDDEN/SUBACCOUNT_SUSPENDED)
//
// Usage: node scripts/mock-biometrics.mjs [port]   → base http://127.0.0.1:<port>/v1
// Special subaccounts (X-Subaccount-Id header):
//   00000000-0000-4000-8000-000000000402 → 402 QUOTA_EXCEEDED
//   00000000-0000-4000-8000-000000000403 → 403 SUBACCOUNT_SUSPENDED
// Special session: GET /v1/sessions/00000000-0000-4000-8000-00000000a000 → APPROVED with decision and checks.
import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { appendFileSync } from 'node:fs'

const PORT = Number(process.argv[2] ?? process.env.PORT ?? 4010)
const LOG = process.env.MOCK_LOG // JSONL of every request, so the harness can check headers
const SUB_QUOTA = '00000000-0000-4000-8000-000000000402'
const SUB_SUSPENDED = '00000000-0000-4000-8000-000000000403'
const APPROVED_ID = '00000000-0000-4000-8000-00000000a000'
const FLOWS = ['ONBOARDING', 'AUTHENTICATION', 'ENROLLMENT', 'LIVENESS_ONLY', 'DEDUP']
const sessions = new Map()

function envelope(id, input, status = 'SESSION_OPEN') {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + 15 * 60_000).toISOString()
  return {
    sessionId: id,
    modality: 'face',
    flow: input.flow,
    provider: 'OPENSOURCE',
    assurance: 'ENHANCED',
    evaluation: { profileId: 'pad-l1-2026-09', label: 'Candidato ISO/IEC 30107-3 Nível 1', standard: 'ISO/IEC 30107-3', conforms: true, certified: false, violations: [] },
    status,
    attempt: 0,
    maxAttempts: 3,
    subjectRef: null,
    customerId: input.customerId ?? null,
    purpose: input.purpose,
    reference: null,
    capture: null,
    metadata: input.metadata ?? null,
    enrollment: null,
    decision: null,
    checks: [],
    evidence: null,
    cost: { amount: '0.0000', currency: 'BRL', estimated: true },
    raw: {},
    createdAt: now.toISOString(),
    capturedAt: null,
    evaluatedAt: null,
    expiresAt,
    elapsedMs: null,
    subaccountId: input.subaccountId ?? null,
  }
}

const engine = (model) => ({ name: 'face-engine', model, version: '2026.09.20' })
sessions.set(APPROVED_ID, {
  ...envelope(APPROVED_ID, { flow: 'LIVENESS_ONLY', purpose: 'abertura de conta' }, 'APPROVED'),
  attempt: 1,
  decision: { outcome: 'APPROVED', reasons: [], policyId: 'p1', reviewRequired: false, policyOverride: null },
  checks: [
    { kind: 'quality.capture', status: 'PASSED', score: 0.91, threshold: 0.6, reasons: [], engine: engine('yunet') },
    { kind: 'liveness.passive', status: 'PASSED', score: 0.97, threshold: 0.8, reasons: [], engine: engine('minifasnet') },
    { kind: 'liveness.active', status: 'PASSED', score: 1, threshold: 1, reasons: [], engine: engine('mediapipe') },
  ],
  evaluatedAt: new Date().toISOString(),
})

function send(res, status, body, headers = {}) {
  const raw = body === undefined ? '' : JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json', 'x-trace-id': randomUUID().replace(/-/g, ''), ...headers })
  res.end(raw)
}

const fail = (res, status, error, message, details) => send(res, status, { error, message, ...(details ? { details } : {}) })

createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    const url = new URL(req.url, 'http://mock')
    if (LOG) appendFileSync(LOG, JSON.stringify({ method: req.method, path: url.pathname, headers: req.headers }) + '\n')
    if (url.pathname === '/health') return send(res, 200, { status: 'ok' })
    const credential = req.headers['x-api-key'] || (req.headers.authorization ?? '').replace(/^(ApiKey|Bearer) /, '')
    if (!credential) return fail(res, 401, 'UNAUTHORIZED', 'Missing or invalid authorization header', { code: 'MISSING_AUTHORIZATION' })
    const subaccount = req.headers['x-subaccount-id']
    if (subaccount === SUB_SUSPENDED) {
      return fail(res, 403, 'FORBIDDEN', 'Subconta suspensa', { code: 'SUBACCOUNT_SUSPENDED', subaccountId: subaccount, reason: 'inadimplência' })
    }

    const m = url.pathname.match(/^\/v1\/sessions(?:\/([^/]+))?(?:\/(cancel))?$/)
    if (!m) return fail(res, 404, 'NOT_FOUND', 'Route not found')
    const [, id, action] = m

    if (req.method === 'POST' && !id) {
      let input
      try {
        input = JSON.parse(body || '{}')
      } catch {
        input = {}
      }
      input = input.data?.attributes ?? input
      if (!FLOWS.includes(input.flow) || typeof input.purpose !== 'string' || input.purpose.length < 3 || input.purpose.length > 120) {
        return send(res, 400, { error: 'VALIDATION', details: { _errors: [], ...(FLOWS.includes(input.flow) ? {} : { flow: { _errors: ['Invalid enum value'] } }) } })
      }
      if (subaccount === SUB_QUOTA) {
        return fail(res, 402, 'PAYMENT_REQUIRED', 'Cota mensal da subconta atingida', {
          code: 'QUOTA_EXCEEDED',
          subaccountId: subaccount,
          monthlyQuota: 500,
          used: 500,
          periodStart: '2026-09-01T03:00:00.000Z',
          periodEnd: '2026-10-01T03:00:00.000Z',
        })
      }
      const sessionId = randomUUID()
      const env = envelope(sessionId, { ...input, subaccountId: subaccount ?? null })
      sessions.set(sessionId, env)
      const token = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sid: sessionId })).toString('base64url') + '.mock'
      return send(res, 201, {
        data: {
          ...env,
          handoff: {
            captureUrl: `https://biometrics.bb.stg.catalisa.app/biometrics/capture/${token}`,
            captureToken: token,
            captureMode: 'RAW_FRAMES',
            challenge: { script: ['SMILE', 'TURN_LEFT', 'BLINK'], timeoutMs: 22000, perGestureMs: 6500, slotsMs: [5200, 6100, 4800] },
            expiresAt: env.expiresAt,
          },
        },
      })
    }
    if (req.method === 'GET' && !id) {
      const all = [...sessions.values()].filter((s) => !url.searchParams.get('status') || s.status === url.searchParams.get('status'))
      const page = Number(url.searchParams.get('page[number]') ?? 1)
      const size = Math.min(100, Number(url.searchParams.get('page[size]') ?? 20))
      return send(res, 200, { data: all.slice((page - 1) * size, page * size), meta: { total: all.length, page: { number: page, size } } })
    }
    const session = sessions.get(id)
    if (!session) return fail(res, 404, 'NOT_FOUND', 'BiometricsSession not found')
    if (req.method === 'GET' && !action) return send(res, 200, { data: session })
    if (req.method === 'POST' && action === 'cancel') {
      if (!['SESSION_OPEN', 'RETRY_ALLOWED', 'ERROR', 'PROCESSING'].includes(session.status)) {
        return fail(res, 400, 'BAD_REQUEST', `Sessão em ${session.status} não pode ser cancelada`)
      }
      session.status = 'CANCELLED'
      return send(res, 200, { data: session })
    }
    return fail(res, 404, 'NOT_FOUND', 'Route not found')
  })
}).listen(PORT, '127.0.0.1', () => console.log(`biometrics mock at http://127.0.0.1:${PORT}/v1`))
