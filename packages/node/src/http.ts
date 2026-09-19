import { BiometricsError, ConnectionError, RateLimitError, errorFromResponse } from './errors'

export const DEFAULT_BASE_URL = 'https://api.biometrics.catalisa.app/v1'
export const SDK_VERSION = '0.1.0'

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export interface HttpOptions {
  apiKey?: string
  accessToken?: string
  baseUrl: string
  timeoutMs: number
  maxRetries: number
  subaccountId?: string
  fetch: FetchLike
  userAgent?: string
  /** Para teste: substitui a espera entre tentativas. */
  sleep?: (ms: number) => Promise<void>
}

export interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  query?: Record<string, string | number | undefined>
  body?: unknown
  /** multipart (captura própria) — já montado; não passa por JSON. */
  form?: FormData
  headers?: Record<string, string>
  /**
   * Pode repetir em 5xx e erro de rede? Só leituras. POST de criação NUNCA repete nesses casos:
   * o BB não aceita Idempotency-Key, e repetir após um 5xx pode abrir duas sessões (e gastar cota).
   * 429 repete sempre: o limitador recusa ANTES do handler, então nada foi feito.
   */
  idempotent: boolean
  timeoutMs?: number
  signal?: AbortSignal
  /** `false` = não envia a credencial do cliente (captura própria usa o captureToken). */
  auth?: boolean
}

export class HttpClient {
  constructor(private readonly opts: HttpOptions) {
    if (!opts.apiKey && !opts.accessToken) throw new Error('Biometrics: informe apiKey (ou accessToken)')
  }

  async request<T>(req: RequestOptions): Promise<T> {
    const url = this.url(req.path, req.query)
    let attempt = 0
    for (;;) {
      try {
        return await this.once<T>(url, req)
      } catch (err) {
        const retryable =
          err instanceof RateLimitError ||
          (req.idempotent && err instanceof BiometricsError && (err.status >= 500 || err instanceof ConnectionError))
        if (!retryable || attempt >= this.opts.maxRetries || req.signal?.aborted) throw err
        await (this.opts.sleep ?? sleep)(this.backoff(attempt, err as BiometricsError))
        attempt++
      }
    }
  }

  private backoff(attempt: number, err: BiometricsError): number {
    if (err instanceof RateLimitError && err.retryAfter != null) return Math.min(err.retryAfter * 1000, 30_000)
    const base = 500 * 2 ** attempt
    return Math.min(base + Math.floor(Math.random() * base * 0.25), 8_000)
  }

  private url(path: string, query?: RequestOptions['query']): string {
    const base = this.opts.baseUrl.replace(/\/+$/, '')
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== '') qs.set(k, String(v))
    const s = qs.toString()
    return `${base}${path}${s ? `?${s}` : ''}`
  }

  private async once<T>(url: string, req: RequestOptions): Promise<T> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': this.opts.userAgent ?? `catalisa-biometrics-node/${SDK_VERSION}`,
      ...req.headers,
    }
    if (req.auth !== false) {
      if (this.opts.accessToken) headers.Authorization = `Bearer ${this.opts.accessToken}`
      else if (this.opts.apiKey) headers['X-API-Key'] = this.opts.apiKey
      if (this.opts.subaccountId) headers['X-Subaccount-Id'] = this.opts.subaccountId
    }

    let body: BodyInit | undefined
    if (req.form) body = req.form
    else if (req.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify(req.body)
    }

    const controller = new AbortController()
    const timeoutMs = req.timeoutMs ?? this.opts.timeoutMs
    const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs)
    const onAbort = () => controller.abort(req.signal?.reason)
    req.signal?.addEventListener('abort', onAbort, { once: true })

    let res: Response
    try {
      res = await this.opts.fetch(url, { method: req.method, headers, body, signal: controller.signal })
    } catch (e) {
      const timedOut = controller.signal.aborted && !req.signal?.aborted
      throw new ConnectionError(timedOut ? `Sem resposta em ${timeoutMs} ms` : `Falha de conexão: ${(e as Error).message}`, {
        status: 0,
        code: timedOut ? 'TIMEOUT' : 'CONNECTION',
      })
    } finally {
      clearTimeout(timer)
      req.signal?.removeEventListener('abort', onAbort)
    }

    const text = await res.text()
    let parsed: unknown = undefined
    if (text) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = text
      }
    }
    if (!res.ok) throw errorFromResponse(res.status, parsed, res.headers)
    return parsed as T
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
