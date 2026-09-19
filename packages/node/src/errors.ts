/**
 * Typed errors. Every API error becomes a `BiometricsError` (or a subclass) with:
 *  - `status`: HTTP status (0 when there was no response);
 *  - `code`: the most specific code the server sent — `details.code` (e.g. QUOTA_EXCEEDED,
 *    SUBACCOUNT_SUSPENDED, TOKEN_EXPIRED) and, when absent, `error` (e.g. VALIDATION, NOT_FOUND);
 *  - `requestId`: the response trace id (`x-request-id` or `x-trace-id`), for support.
 */
export class BiometricsError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId: string | null
  readonly details: unknown
  readonly body: unknown

  constructor(message: string, opts: { status: number; code: string; requestId?: string | null; details?: unknown; body?: unknown }) {
    super(message)
    this.name = new.target.name
    this.status = opts.status
    this.code = opts.code
    this.requestId = opts.requestId ?? null
    this.details = opts.details
    this.body = opts.body
  }
}

/** 401 — missing, invalid, revoked or expired key. */
export class AuthenticationError extends BiometricsError {}
/** 403 without a subaccount sub-code — missing permission, or subject locked (`subject.locked`). */
export class PermissionError extends BiometricsError {}
/** 402 `QUOTA_EXCEEDED` — the subaccount's monthly quota is used up. `details` has `monthlyQuota`, `used`, `periodEnd`. */
export class QuotaExceededError extends BiometricsError {}
/** 403 `SUBACCOUNT_SUSPENDED` — the subaccount was suspended by the organization. */
export class SubaccountSuspendedError extends BiometricsError {}
/** 400 — invalid body, missing reference required by the flow, insufficient assurance. */
export class ValidationError extends BiometricsError {}
/** 404 — session, template or file not found (or owned by another organization/subaccount). */
export class NotFoundError extends BiometricsError {}
/** 429 — rate limited. `retryAfter` in seconds, when the server provides it. */
export class RateLimitError extends BiometricsError {
  readonly retryAfter: number | null
  constructor(message: string, opts: ConstructorParameters<typeof BiometricsError>[1] & { retryAfter?: number | null }) {
    super(message, opts)
    this.retryAfter = opts.retryAfter ?? null
  }
}
/** 5xx — server failure or engine unavailable (503). */
export class ServerError extends BiometricsError {}
/** No response: network, DNS, TLS or timeout (`code` = `TIMEOUT` or `CONNECTION`). */
export class ConnectionError extends BiometricsError {}
/** Webhook signature missing, invalid or outside the time tolerance. */
export class WebhookVerificationError extends BiometricsError {}

interface ErrorBody {
  error?: unknown
  message?: unknown
  error_description?: unknown
  details?: unknown
  retry_after?: unknown
}

/** Builds the right error class from a server response. */
export function errorFromResponse(status: number, body: unknown, headers: Headers): BiometricsError {
  const b: ErrorBody = body && typeof body === 'object' ? (body as ErrorBody) : {}
  const details = b.details
  const detailCode =
    details && typeof details === 'object' && !Array.isArray(details) && typeof (details as { code?: unknown }).code === 'string'
      ? ((details as { code: string }).code as string)
      : undefined
  const topCode = typeof b.error === 'string' ? b.error : undefined
  const code = detailCode ?? topCode ?? `HTTP_${status}`
  const message =
    (typeof b.message === 'string' && b.message) ||
    (typeof b.error_description === 'string' && b.error_description) ||
    `Biometrics API responded with HTTP ${status}`
  const requestId = headers.get('x-request-id') ?? headers.get('x-trace-id')
  const opts = { status, code, requestId, details, body }

  if (status === 402 || code === 'QUOTA_EXCEEDED') return new QuotaExceededError(message, opts)
  if (code === 'SUBACCOUNT_SUSPENDED') return new SubaccountSuspendedError(message, opts)
  if (status === 401) return new AuthenticationError(message, opts)
  if (status === 403) return new PermissionError(message, opts)
  if (status === 404) return new NotFoundError(message, opts)
  if (status === 429) {
    const header = Number(headers.get('retry-after'))
    const fromBody = typeof b.retry_after === 'number' ? b.retry_after : NaN
    const retryAfter = Number.isFinite(header) && headers.get('retry-after') !== null ? header : Number.isFinite(fromBody) ? fromBody : null
    return new RateLimitError(message, { ...opts, retryAfter })
  }
  if (status >= 500) return new ServerError(message, opts)
  if (status === 400 || status === 415 || status === 413 || status === 422) return new ValidationError(message, opts)
  return new BiometricsError(message, opts)
}
