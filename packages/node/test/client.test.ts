import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import {
  AuthenticationError,
  Biometrics,
  BiometricsError,
  ConnectionError,
  NotFoundError,
  PermissionError,
  QuotaExceededError,
  RateLimitError,
  ServerError,
  SubaccountSuspendedError,
  ValidationError,
  verifyEvidenceSignature,
} from '../src'

const vectors = JSON.parse(readFileSync(new URL('../../../vectors/vectors.json', import.meta.url), 'utf8'))

type Call = { url: string; init: RequestInit }

function mockFetch(...responses: Array<Response | (() => Response) | Error>) {
  const calls: Call[] = []
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init: init ?? {} })
    const next = responses.length > 1 ? responses.shift()! : responses[0]
    if (next instanceof Error) throw next
    return typeof next === 'function' ? next() : next.clone()
  })
  return { fn, calls }
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

const envelope = {
  sessionId: '5b0e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b',
  modality: 'face',
  flow: 'LIVENESS_ONLY',
  provider: 'OPENSOURCE',
  assurance: 'ENHANCED',
  evaluation: null,
  status: 'SESSION_OPEN',
  attempt: 0,
  maxAttempts: 3,
  subjectRef: null,
  customerId: null,
  purpose: 'test',
  reference: null,
  capture: null,
  metadata: null,
  enrollment: null,
  decision: null,
  checks: [],
  handoff: {
    captureUrl: 'https://biometrics.bb.stg.catalisa.app/biometrics/capture/eyJ',
    captureToken: 'eyJ',
    captureMode: 'RAW_FRAMES',
    expiresAt: '2026-09-18T15:15:00.000Z',
  },
  evidence: null,
  cost: { amount: '0.0000', currency: 'BRL', estimated: true },
  raw: {},
  createdAt: '2026-09-18T15:00:00.000Z',
  capturedAt: null,
  evaluatedAt: null,
  expiresAt: '2026-09-18T15:15:00.000Z',
  elapsedMs: null,
}

const noSleep = async () => {}

describe('Biometrics — requests', () => {
  it('creates a session: POST /sessions with X-API-Key, JSON and the default base URL', async () => {
    const { fn, calls } = mockFetch(json(201, { data: envelope }))
    const bio = new Biometrics({ apiKey: 'pk.sk', fetch: fn })
    const s = await bio.sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abertura de conta' })
    expect(s.handoff.captureUrl).toContain('/capture/')
    expect(calls[0].url).toBe('https://api.biometrics.catalisa.app/v1/sessions')
    expect(calls[0].init.method).toBe('POST')
    const h = calls[0].init.headers as Record<string, string>
    expect(h['X-API-Key']).toBe('pk.sk')
    expect(h['Content-Type']).toBe('application/json')
    expect(h['X-Subaccount-Id']).toBeUndefined()
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ flow: 'LIVENESS_ONLY', purpose: 'abertura de conta' })
  })

  it('custom baseUrl (no double slash), subaccountId and optional Idempotency-Key', async () => {
    const { fn, calls } = mockFetch(json(201, { data: envelope }))
    const bio = new Biometrics({ apiKey: 'k', baseUrl: 'https://biometrics.bb.stg.catalisa.app/biometrics/api/v1/', subaccountId: 'sub-1', fetch: fn })
    await bio.sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'x y z' }, { idempotencyKey: 'order-42' })
    expect(calls[0].url).toBe('https://biometrics.bb.stg.catalisa.app/biometrics/api/v1/sessions')
    const h = calls[0].init.headers as Record<string, string>
    expect(h['X-Subaccount-Id']).toBe('sub-1')
    expect(h['Idempotency-Key']).toBe('order-42')
  })

  it('accessToken uses Authorization: Bearer instead of X-API-Key', async () => {
    const { fn, calls } = mockFetch(json(200, { data: envelope }))
    await new Biometrics({ accessToken: 'jwt', fetch: fn }).sessions.get(envelope.sessionId)
    const h = calls[0].init.headers as Record<string, string>
    expect(h.Authorization).toBe('Bearer jwt')
    expect(h['X-API-Key']).toBeUndefined()
  })

  it('requires a credential', () => {
    expect(() => new Biometrics({ fetch: vi.fn() })).toThrow(/apiKey/)
  })

  it('get, cancel and evidence on the server paths (escaped id)', async () => {
    const { fn, calls } = mockFetch(json(200, { data: envelope }))
    const bio = new Biometrics({ apiKey: 'k', fetch: fn })
    await bio.sessions.get('a/b')
    await bio.sessions.cancel('id1')
    await bio.sessions.evidence('id1')
    await bio.sessions.verifyEvidenceOnServer('id1')
    expect(calls.map((c) => `${c.init.method} ${c.url.replace('https://api.biometrics.catalisa.app/v1', '')}`)).toEqual([
      'GET /sessions/a%2Fb',
      'POST /sessions/id1/cancel',
      'GET /sessions/id1/evidence',
      'GET /sessions/id1/evidence/verify',
    ])
  })

  it('list: page[number]/page[size] pagination and filters; returns data + meta', async () => {
    const { fn, calls } = mockFetch(json(200, { data: [envelope], meta: { total: 1, page: { number: 2, size: 10 } } }))
    const bio = new Biometrics({ apiKey: 'k', fetch: fn })
    const r = await bio.sessions.list({ page: 2, pageSize: 10, status: 'APPROVED', from: new Date('2026-09-01T00:00:00Z'), subaccountId: 's1' })
    expect(r.meta.total).toBe(1)
    const u = new URL(calls[0].url)
    expect(u.searchParams.get('page[number]')).toBe('2')
    expect(u.searchParams.get('page[size]')).toBe('10')
    expect(u.searchParams.get('status')).toBe('APPROVED')
    expect(u.searchParams.get('from')).toBe('2026-09-01T00:00:00.000Z')
    expect(u.searchParams.get('subaccountId')).toBe('s1')
    expect(u.searchParams.has('flow')).toBe(false)
  })

  it('submitCapture: multipart with video, telemetry, SDK channel and the captureToken as Bearer (no API key)', async () => {
    const { fn, calls } = mockFetch(json(200, { data: { sessionId: 'id1', status: 'COMPLETED' } }))
    const bio = new Biometrics({ apiKey: 'secret', fetch: fn })
    const r = await bio.sessions.submitCapture('id1', 'cap-token', { video: new Blob([new Uint8Array([1, 2, 3])], { type: 'video/webm' }), telemetry: { schemaVersion: 1 } })
    expect(r.status).toBe('COMPLETED')
    expect(calls[0].url).toMatch(/\/sessions\/id1\/captures$/)
    const h = calls[0].init.headers as Record<string, string>
    expect(h.Authorization).toBe('Bearer cap-token')
    expect(h['X-API-Key']).toBeUndefined()
    const form = calls[0].init.body as FormData
    expect(form.get('channel')).toBe('SDK')
    expect(JSON.parse(form.get('telemetry') as string)).toEqual({ schemaVersion: 1 })
    expect((form.get('video') as File).name).toBe('challenge.webm')
  })
})

describe('Biometrics — typed errors (server format)', () => {
  const cases: Array<[string, Response, new (...a: never[]) => BiometricsError, string]> = [
    ['401', json(401, { error: 'UNAUTHORIZED', message: 'Invalid API key', statusCode: 401, details: { code: 'API_KEY_INVALID' } }), AuthenticationError, 'API_KEY_INVALID'],
    [
      '402 quota',
      json(402, { error: 'PAYMENT_REQUIRED', message: 'Monthly quota reached', details: { code: 'QUOTA_EXCEEDED', subaccountId: 's', monthlyQuota: 500, used: 500 } }),
      QuotaExceededError,
      'QUOTA_EXCEEDED',
    ],
    ['403 suspended', json(403, { error: 'FORBIDDEN', message: 'Subaccount suspended', details: { code: 'SUBACCOUNT_SUSPENDED', reason: 'unpaid' } }), SubaccountSuspendedError, 'SUBACCOUNT_SUSPENDED'],
    ['403 permission', json(403, { error: 'FORBIDDEN', message: 'Insufficient permissions' }), PermissionError, 'FORBIDDEN'],
    ['400', json(400, { error: 'VALIDATION', details: { flow: { _errors: ['x'] } } }), ValidationError, 'VALIDATION'],
    ['404', json(404, { error: 'NOT_FOUND', message: 'BiometricsSession not found' }), NotFoundError, 'NOT_FOUND'],
  ]
  for (const [name, res, klass, code] of cases) {
    it(name, async () => {
      const { fn } = mockFetch(res)
      const err = await new Biometrics({ apiKey: 'k', fetch: fn, sleep: noSleep }).sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abc' }).catch((e) => e)
      expect(err).toBeInstanceOf(klass)
      expect(err).toBeInstanceOf(BiometricsError)
      expect(err.code).toBe(code)
      expect(err.status).toBe(res.status)
    })
  }

  it('402 exposes details (monthlyQuota/used) and requestId from x-trace-id', async () => {
    const { fn } = mockFetch(json(402, { error: 'PAYMENT_REQUIRED', message: 'm', details: { code: 'QUOTA_EXCEEDED', monthlyQuota: 10, used: 10 } }, { 'x-trace-id': 'tr-1' }))
    const err = (await new Biometrics({ apiKey: 'k', fetch: fn }).sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abc' }).catch((e) => e)) as QuotaExceededError
    expect(err.details).toMatchObject({ monthlyQuota: 10, used: 10 })
    expect(err.requestId).toBe('tr-1')
  })

  it('429 from the global limiter (too_many_requests shape) becomes RateLimitError with retryAfter', async () => {
    const { fn } = mockFetch(json(429, { error: 'too_many_requests', error_description: 'Rate limit exceeded.', retry_after: 7 }, { 'retry-after': '7' }))
    const err = await new Biometrics({ apiKey: 'k', fetch: fn, maxRetries: 0 }).sessions.get('x').catch((e) => e)
    expect(err).toBeInstanceOf(RateLimitError)
    expect(err.retryAfter).toBe(7)
    expect(err.message).toBe('Rate limit exceeded.')
  })
})

describe('Biometrics — retries', () => {
  it('reads retry on 503 and on network errors, with backoff', async () => {
    const sleeps: number[] = []
    const { fn } = mockFetch(json(503, { error: 'SERVICE_UNAVAILABLE' }), new TypeError('fetch failed'), json(200, { data: envelope }))
    const bio = new Biometrics({ apiKey: 'k', fetch: fn, sleep: async (ms) => void sleeps.push(ms) })
    const s = await bio.sessions.get('x')
    expect(s.sessionId).toBe(envelope.sessionId)
    expect(fn).toHaveBeenCalledTimes(3)
    expect(sleeps).toHaveLength(2)
    expect(sleeps[1]).toBeGreaterThanOrEqual(sleeps[0])
  })

  it('gives up after maxRetries and throws ServerError', async () => {
    const { fn } = mockFetch(json(500, { message: 'Internal server error', statusCode: 500 }))
    const err = await new Biometrics({ apiKey: 'k', fetch: fn, sleep: noSleep, maxRetries: 2 }).sessions.get('x').catch((e) => e)
    expect(err).toBeInstanceOf(ServerError)
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it('creation is NOT retried on 5xx or network errors (avoids duplicate sessions)', async () => {
    const a = mockFetch(json(503, { error: 'SERVICE_UNAVAILABLE' }))
    await expect(new Biometrics({ apiKey: 'k', fetch: a.fn, sleep: noSleep }).sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abc' })).rejects.toBeInstanceOf(ServerError)
    expect(a.fn).toHaveBeenCalledTimes(1)
    const b = mockFetch(new TypeError('socket hang up'))
    await expect(new Biometrics({ apiKey: 'k', fetch: b.fn, sleep: noSleep }).sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abc' })).rejects.toBeInstanceOf(ConnectionError)
    expect(b.fn).toHaveBeenCalledTimes(1)
  })

  it('creation is retried on 429 honoring Retry-After', async () => {
    const sleeps: number[] = []
    const { fn } = mockFetch(json(429, { error: 'too_many_requests' }, { 'retry-after': '2' }), json(201, { data: envelope }))
    const s = await new Biometrics({ apiKey: 'k', fetch: fn, sleep: async (ms) => void sleeps.push(ms) }).sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abc' })
    expect(s.sessionId).toBe(envelope.sessionId)
    expect(sleeps).toEqual([2000])
  })

  it('does not retry 4xx', async () => {
    const { fn } = mockFetch(json(404, { error: 'NOT_FOUND' }))
    await expect(new Biometrics({ apiKey: 'k', fetch: fn, sleep: noSleep }).sessions.get('x')).rejects.toBeInstanceOf(NotFoundError)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('timeout becomes ConnectionError TIMEOUT', async () => {
    const fn = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_r, reject) => init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))))
    )
    const err = await new Biometrics({ apiKey: 'k', fetch: fn, timeoutMs: 20, maxRetries: 0 }).sessions.get('x').catch((e) => e)
    expect(err).toBeInstanceOf(ConnectionError)
    expect(err.code).toBe('TIMEOUT')
  })
})

describe('evidence — Ed25519 (vector generated by the server code)', () => {
  const e = vectors.evidence
  const keys = e.evidenceKeysResponse.data

  it('verifies offline the signature produced by BiometricsEvidenceSignatureService', () => {
    const r = verifyEvidenceSignature({ sessionId: e.sessionId, attempt: e.attempt, bundleHash: e.evidence.bundleHash, signature: e.evidence.signature }, keys)
    expect(r).toMatchObject({ valid: true, unknownKey: false, retiredAt: null })
  })

  it('rejects a different attempt, bundleHash or signedAt, and an unknown keyId', () => {
    const base = { sessionId: e.sessionId, attempt: e.attempt, bundleHash: e.evidence.bundleHash, signature: e.evidence.signature }
    expect(verifyEvidenceSignature({ ...base, attempt: 2 }, keys).valid).toBe(false)
    expect(verifyEvidenceSignature({ ...base, bundleHash: 'ff' + base.bundleHash.slice(2) }, keys).valid).toBe(false)
    expect(verifyEvidenceSignature({ ...base, signature: { ...base.signature, signedAt: '2026-01-01T00:00:00.000Z' } }, keys).valid).toBe(false)
    expect(verifyEvidenceSignature({ ...base, signature: { ...base.signature, keyId: 'ev-x' } }, keys)).toMatchObject({ valid: false, unknownKey: true })
  })

  it('bio.evidence.verify fetches envelope + keys and verifies locally', async () => {
    const env = { ...envelope, sessionId: e.sessionId, attempt: e.attempt, status: 'APPROVED', evidence: { bundleHash: e.evidence.bundleHash, signature: e.evidence.signature, artifacts: [] } }
    const { fn, calls } = mockFetch(json(200, { data: env }), json(200, e.evidenceKeysResponse))
    const r = await new Biometrics({ apiKey: 'k', fetch: fn }).evidence.verify(e.sessionId)
    expect(r.valid).toBe(true)
    expect(calls[1].url).toMatch(/\/evidence-keys$/)
  })
})

describe('Biometrics — Retry-After absent', () => {
  it('429 without Retry-After header falls back to retry_after in the body, then to exponential backoff', async () => {
    const sleeps: number[] = []
    const { fn } = mockFetch(json(429, { error: 'too_many_requests', retry_after: 3 }), json(429, { error: 'RATE_LIMITED' }), json(200, { data: envelope }))
    await new Biometrics({ apiKey: 'k', fetch: fn, sleep: async (ms) => void sleeps.push(ms) }).sessions.get('x')
    expect(sleeps[0]).toBe(3000)
    expect(sleeps[1]).toBeGreaterThanOrEqual(1000)
  })
})
