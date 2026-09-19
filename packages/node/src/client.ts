import { DEFAULT_BASE_URL, HttpClient, type FetchLike } from './http'
import { BiometricsError } from './errors'
import { verifyEvidenceSignature, type OfflineVerification } from './evidence'
import * as webhooks from './webhooks'
import type {
  CreateSessionParams,
  CreatedSession,
  EvidenceKey,
  EvidenceVerification,
  EvidenceWithUrls,
  ListSessionsParams,
  SessionEnvelope,
  SessionList,
} from './types'

export interface BiometricsOptions {
  /** API key (`X-API-Key`). Organization-level or subaccount-level. */
  apiKey?: string
  /** Alternative to the key: an IAM access JWT (`Authorization: Bearer`). */
  accessToken?: string
  /** Default `https://api.biometrics.catalisa.app/v1`. Staging: `https://biometrics.bb.stg.catalisa.app/biometrics/api/v1`. */
  baseUrl?: string
  /** Per-request timeout. Default 30 000 ms. */
  timeoutMs?: number
  /** Retries on 429 (always) and on 5xx/network errors (reads only). Default 2. */
  maxRetries?: number
  /** Act as this subaccount (`X-Subaccount-Id` header) using an organization key. */
  subaccountId?: string
  /** Custom `fetch` (tests, proxies). Default: native `fetch` from Node >= 18. */
  fetch?: FetchLike
  /** Wait between retries (injectable in tests). */
  sleep?: (ms: number) => Promise<void>
}

interface Data<T> {
  data: T
}

export interface CallOptions {
  signal?: AbortSignal
  timeoutMs?: number
}

export interface CreateOptions extends CallOptions {
  /**
   * Sent as `Idempotency-Key`. NOTE: the server (origin/main as of 2026-09-18) does not deduplicate
   * on this header yet; for the same reason the SDK never retries creation on 5xx/network errors.
   */
  idempotencyKey?: string
}

export interface CaptureSubmission {
  /** Challenge video (webm or mp4, up to 16 MB and 24 s). */
  video: Blob
  fileName?: string
  /** Device telemetry (JSON object up to 64 KB). */
  telemetry?: Record<string, unknown>
  capturedAt?: Date | string
}

class Sessions {
  constructor(private readonly http: HttpClient) {}

  /** Opens a session. Returns the envelope with `handoff.captureUrl` to send the person to capture. */
  async create(params: CreateSessionParams, opts: CreateOptions = {}): Promise<CreatedSession> {
    const res = await this.http.request<Data<CreatedSession>>({
      method: 'POST',
      path: '/sessions',
      body: params,
      idempotent: false,
      headers: opts.idempotencyKey ? { 'Idempotency-Key': opts.idempotencyKey } : undefined,
      signal: opts.signal,
      timeoutMs: opts.timeoutMs,
    })
    return res.data
  }

  /** The full envelope: status, decision, checks, evidence. The result comes from here (or from the webhook). */
  async get(sessionId: string, opts: CallOptions = {}): Promise<SessionEnvelope> {
    const res = await this.http.request<Data<SessionEnvelope>>({ method: 'GET', path: `/sessions/${enc(sessionId)}`, idempotent: true, ...opts })
    return res.data
  }

  async list(params: ListSessionsParams = {}, opts: CallOptions = {}): Promise<SessionList> {
    return this.http.request<SessionList>({
      method: 'GET',
      path: '/sessions',
      idempotent: true,
      query: {
        'page[number]': params.page,
        'page[size]': params.pageSize,
        status: params.status,
        flow: params.flow,
        customerId: params.customerId,
        subjectCpf: params.subjectCpf,
        from: iso(params.from),
        to: iso(params.to),
        subaccountId: params.subaccountId,
      },
      ...opts,
    })
  }

  /** Cancels an open session. Terminal session → 400 (`ValidationError`). */
  async cancel(sessionId: string, opts: CallOptions = {}): Promise<SessionEnvelope> {
    const res = await this.http.request<Data<SessionEnvelope>>({ method: 'POST', path: `/sessions/${enc(sessionId)}/cancel`, idempotent: false, ...opts })
    return res.data
  }

  /** Hashes, signature and short-lived artifact URLs. */
  async evidence(sessionId: string, opts: CallOptions = {}): Promise<EvidenceWithUrls> {
    const res = await this.http.request<Data<EvidenceWithUrls>>({ method: 'GET', path: `/sessions/${enc(sessionId)}/evidence`, idempotent: true, ...opts })
    return res.data
  }

  /** The server checks the evidence signature. To check it WITHOUT Catalisa, use `evidence.verify`. */
  async verifyEvidenceOnServer(sessionId: string, opts: CallOptions = {}): Promise<EvidenceVerification> {
    const res = await this.http.request<Data<EvidenceVerification>>({ method: 'GET', path: `/sessions/${enc(sessionId)}/evidence/verify`, idempotent: true, ...opts })
    return res.data
  }

  /**
   * Custom capture (native app with its own camera): uploads the video with the handoff's `captureToken`.
   * The response is the PUBLIC view (no score, no decision reasons) — the result still comes
   * from the webhook or `sessions.get`.
   */
  async submitCapture(sessionId: string, captureToken: string, capture: CaptureSubmission, opts: CallOptions = {}): Promise<Record<string, unknown>> {
    const form = new FormData()
    form.append('video', capture.video, capture.fileName ?? (capture.video.type.includes('mp4') ? 'challenge.mp4' : 'challenge.webm'))
    if (capture.telemetry) form.append('telemetry', JSON.stringify(capture.telemetry))
    if (capture.capturedAt) form.append('capturedAt', iso(capture.capturedAt)!)
    form.append('channel', 'SDK')
    const res = await this.http.request<Data<Record<string, unknown>>>({
      method: 'POST',
      path: `/sessions/${enc(sessionId)}/captures`,
      form,
      headers: { Authorization: `Bearer ${captureToken}` },
      auth: false,
      idempotent: false,
      ...opts,
    })
    return res.data
  }
}

class Evidence {
  constructor(private readonly http: HttpClient, private readonly sessions: Sessions) {}

  /** The organization's Ed25519 public keys (including retired ones, to verify the past). */
  async keys(opts: CallOptions = {}): Promise<EvidenceKey[]> {
    const res = await this.http.request<Data<EvidenceKey[]>>({ method: 'GET', path: '/evidence-keys', idempotent: true, ...opts })
    return res.data
  }

  /**
   * Verifies the evidence signature locally with the public key (Ed25519). Fetches the envelope
   * and the keys; if you already have them, call `verifyEvidenceSignature` directly.
   */
  async verify(sessionId: string, opts: CallOptions & { keys?: EvidenceKey[] } = {}): Promise<OfflineVerification> {
    const { keys: given, ...call } = opts
    const session = await this.sessions.get(sessionId, call)
    const sig = session.evidence?.signature
    if (!session.evidence || !sig) {
      throw new BiometricsError('Session has no signed evidence', { status: 0, code: 'EVIDENCE_NOT_SIGNED' })
    }
    const keys = given ?? (await this.keys(call))
    return verifyEvidenceSignature({ sessionId: session.sessionId, attempt: session.attempt, bundleHash: session.evidence.bundleHash, signature: sig }, keys)
  }
}

export class Biometrics {
  readonly sessions: Sessions
  readonly evidence: Evidence
  /** Webhook verification (needs no API key; static helpers). */
  readonly webhooks = webhooks
  static readonly webhooks = webhooks

  constructor(opts: BiometricsOptions) {
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined)
    if (!f) throw new Error('Biometrics: native fetch is not available (requires Node >= 18)')
    const http = new HttpClient({
      apiKey: opts.apiKey,
      accessToken: opts.accessToken,
      baseUrl: opts.baseUrl ?? DEFAULT_BASE_URL,
      timeoutMs: opts.timeoutMs ?? 30_000,
      maxRetries: opts.maxRetries ?? 2,
      subaccountId: opts.subaccountId,
      fetch: f,
      sleep: opts.sleep,
    })
    this.sessions = new Sessions(http)
    this.evidence = new Evidence(http, this.sessions)
  }
}

function enc(id: string): string {
  if (!id) throw new Error('Biometrics: empty id')
  return encodeURIComponent(id)
}

function iso(v: string | Date | undefined): string | undefined {
  return v instanceof Date ? v.toISOString() : v
}
