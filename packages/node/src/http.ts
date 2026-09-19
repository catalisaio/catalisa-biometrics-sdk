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
  /** For tests: replaces the wait between attempts. */
  sleep?: (ms: number) => Promise<void>
}

export interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  query?: Record<string, string | number | undefined>
  body?: unknown
  /** multipart (custom capture) — already built; not JSON-encoded. */
  form?: FormData
  headers?: Record<string, string>
  /**
   * May it be retried on 5xx and network errors? Reads only. Session creation is NEVER retried
   * in those cases: the server does not honor Idempotency-Key, and retrying after a 5xx could open
   * two sessions (and consume quota twice). 429 is always retried: the rate limiter rejects BEFORE
   * the handler runs, so nothing was done.
   */
  idempotent: boolean
  timeoutMs?: number
  signal?: AbortSignal
  /** `false` = do not send the client credential (custom capture uses the captureToken). */
  auth?: boolean
}

export class HttpClient {
  constructor(private readonly opts: HttpOptions) {
    if (!opts.apiKey && !opts.accessToken) throw new Error('Biometrics: apiKey (or accessToken) is required')
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
      throw new ConnectionError(timedOut ? `No response within ${timeoutMs} ms` : `Connection failed: ${(e as Error).message}`, {
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
