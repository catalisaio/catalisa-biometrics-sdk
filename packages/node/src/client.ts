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
  /** Chave de API (`X-API-Key`). Da organização ou de uma subconta. */
  apiKey?: string
  /** Alternativa à chave: JWT de acesso do IAM (`Authorization: Bearer`). */
  accessToken?: string
  /** Padrão `https://api.biometrics.catalisa.app/v1`. Staging: `https://biometrics.bb.stg.catalisa.app/biometrics/api/v1`. */
  baseUrl?: string
  /** Timeout por requisição. Padrão 30 000 ms. */
  timeoutMs?: number
  /** Repetições em 429 (sempre) e em 5xx/rede (só leituras). Padrão 2. */
  maxRetries?: number
  /** Age como esta subconta (header `X-Subaccount-Id`) com uma chave da organização. */
  subaccountId?: string
  /** `fetch` alternativo (teste, proxy). Padrão: o `fetch` nativo do Node ≥ 18. */
  fetch?: FetchLike
  /** Espera entre tentativas (injetável em teste). */
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
   * Enviado como `Idempotency-Key`. ATENÇÃO: o BB (origin/main de 2026-09-18) ainda não
   * deduplica por esse header; o SDK também não repete a criação em 5xx/rede por isso.
   */
  idempotencyKey?: string
}

export interface CaptureSubmission {
  /** Vídeo do desafio (webm ou mp4, até 16 MB e 24 s). */
  video: Blob
  fileName?: string
  /** Telemetria do dispositivo (objeto JSON até 64 KB). */
  telemetry?: Record<string, unknown>
  capturedAt?: Date | string
}

class Sessions {
  constructor(private readonly http: HttpClient) {}

  /** Abre a sessão. Devolve o envelope com `handoff.captureUrl` para mandar a pessoa à captura. */
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

  /** O envelope completo: status, decisão, checks, evidência. É daqui (ou do webhook) que vem o resultado. */
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

  /** Cancela uma sessão aberta. Terminal → 400 (`ValidationError`). */
  async cancel(sessionId: string, opts: CallOptions = {}): Promise<SessionEnvelope> {
    const res = await this.http.request<Data<SessionEnvelope>>({ method: 'POST', path: `/sessions/${enc(sessionId)}/cancel`, idempotent: false, ...opts })
    return res.data
  }

  /** Hashes, assinatura e URLs temporárias dos artefatos. */
  async evidence(sessionId: string, opts: CallOptions = {}): Promise<EvidenceWithUrls> {
    const res = await this.http.request<Data<EvidenceWithUrls>>({ method: 'GET', path: `/sessions/${enc(sessionId)}/evidence`, idempotent: true, ...opts })
    return res.data
  }

  /** O BB confere a assinatura da evidência no servidor. Para conferir SEM a Catalisa, use `verifyEvidence`. */
  async verifyEvidenceOnServer(sessionId: string, opts: CallOptions = {}): Promise<EvidenceVerification> {
    const res = await this.http.request<Data<EvidenceVerification>>({ method: 'GET', path: `/sessions/${enc(sessionId)}/evidence/verify`, idempotent: true, ...opts })
    return res.data
  }

  /**
   * Captura própria (app nativo com câmera própria): envia o vídeo com o `captureToken` do handoff.
   * A resposta é a visão PÚBLICA (sem score nem motivos de decisão) — o resultado continua vindo
   * pelo webhook ou por `sessions.get`.
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

  /** Chaves públicas Ed25519 da organização (inclui as aposentadas, para verificar o passado). */
  async keys(opts: CallOptions = {}): Promise<EvidenceKey[]> {
    const res = await this.http.request<Data<EvidenceKey[]>>({ method: 'GET', path: '/evidence-keys', idempotent: true, ...opts })
    return res.data
  }

  /**
   * Verifica a assinatura da evidência localmente, com a chave pública (Ed25519). Busca o envelope
   * e as chaves; se você já os tem, use `verifyEvidenceSignature` direto.
   */
  async verify(sessionId: string, opts: CallOptions & { keys?: EvidenceKey[] } = {}): Promise<OfflineVerification> {
    const { keys: given, ...call } = opts
    const session = await this.sessions.get(sessionId, call)
    const sig = session.evidence?.signature
    if (!session.evidence || !sig) {
      throw new BiometricsError('Sessão sem evidência assinada', { status: 0, code: 'EVIDENCE_NOT_SIGNED' })
    }
    const keys = given ?? (await this.keys(call))
    return verifyEvidenceSignature({ sessionId: session.sessionId, attempt: session.attempt, bundleHash: session.evidence.bundleHash, signature: sig }, keys)
  }
}

export class Biometrics {
  readonly sessions: Sessions
  readonly evidence: Evidence
  /** Verificação de webhook (não precisa de chave de API; é estático). */
  readonly webhooks = webhooks
  static readonly webhooks = webhooks

  constructor(opts: BiometricsOptions) {
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined)
    if (!f) throw new Error('Biometrics: fetch nativo indisponível (requer Node >= 18)')
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
  if (!id) throw new Error('Biometrics: id vazio')
  return encodeURIComponent(id)
}

function iso(v: string | Date | undefined): string | undefined {
  return v instanceof Date ? v.toISOString() : v
}
