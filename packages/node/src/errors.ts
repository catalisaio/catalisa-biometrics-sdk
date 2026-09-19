/**
 * Erros tipados. Todo erro de API vira `BiometricsError` (ou uma subclasse), com:
 *  - `status`: HTTP (0 quando não houve resposta);
 *  - `code`: o código mais específico que o BB mandou — `details.code` (ex.: QUOTA_EXCEEDED,
 *    SUBACCOUNT_SUSPENDED, TOKEN_EXPIRED) e, na falta dele, `error` (ex.: VALIDATION, NOT_FOUND);
 *  - `requestId`: o id de rastreio da resposta (`x-request-id` ou `x-trace-id`), para o suporte.
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

/** 401 — chave ausente, inválida, revogada ou expirada. */
export class AuthenticationError extends BiometricsError {}
/** 403 sem subcódigo de subconta — falta permissão, ou titular bloqueado (`subject.locked`). */
export class PermissionError extends BiometricsError {}
/** 402 `QUOTA_EXCEEDED` — cota mensal da subconta atingida. `details` traz `monthlyQuota`, `used`, `periodEnd`. */
export class QuotaExceededError extends BiometricsError {}
/** 403 `SUBACCOUNT_SUSPENDED` — a subconta foi suspensa pela organização. */
export class SubaccountSuspendedError extends BiometricsError {}
/** 400 — corpo inválido, referência exigida pelo fluxo ausente, garantia insuficiente. */
export class ValidationError extends BiometricsError {}
/** 404 — sessão, cadastro ou arquivo inexistente (ou de outra organização/subconta). */
export class NotFoundError extends BiometricsError {}
/** 429 — limite de requisições. `retryAfter` em segundos, quando o servidor informa. */
export class RateLimitError extends BiometricsError {
  readonly retryAfter: number | null
  constructor(message: string, opts: ConstructorParameters<typeof BiometricsError>[1] & { retryAfter?: number | null }) {
    super(message, opts)
    this.retryAfter = opts.retryAfter ?? null
  }
}
/** 5xx — falha do servidor ou motor indisponível (503). */
export class ServerError extends BiometricsError {}
/** Sem resposta: rede, DNS, TLS ou timeout (`code` = `TIMEOUT` ou `CONNECTION`). */
export class ConnectionError extends BiometricsError {}
/** Assinatura de webhook ausente, inválida ou fora da tolerância de tempo. */
export class WebhookVerificationError extends BiometricsError {}

interface ErrorBody {
  error?: unknown
  message?: unknown
  error_description?: unknown
  details?: unknown
  retry_after?: unknown
}

/** Monta o erro certo a partir da resposta do BB. */
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
    `Biometrics respondeu HTTP ${status}`
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
    const retryAfter = Number.isFinite(header) ? header : Number.isFinite(fromBody) ? fromBody : null
    return new RateLimitError(message, { ...opts, retryAfter })
  }
  if (status >= 500) return new ServerError(message, opts)
  if (status === 400 || status === 415 || status === 413 || status === 422) return new ValidationError(message, opts)
  return new BiometricsError(message, opts)
}
