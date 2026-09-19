import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { WebhookVerificationError } from './errors'
import type { WebhookEvent } from './types'

/**
 * Verificação das entregas do Webhooks Engine da Catalisa, exatamente como ele assina
 * (`src/webhooks-engine/utils/crypto.ts` e `services/signing-key.service.ts`):
 *
 *   mensagem   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + corpo cru
 *   assinatura = RSA-SHA256 (PKCS#1 v1.5) com a chave privada da subscription, em base64
 *   header     = x-webhook-signature: "v1=<base64>"; x-webhook-key-id escolhe a chave pública
 *
 * A assinatura é ASSIMÉTRICA: você verifica com a chave PÚBLICA da subscription
 * (`GET /webhooks-engine/api/v1/subscriptions/:id/keys`), não com um segredo compartilhado.
 * O BB não recusa entrega antiga — quem aplica a tolerância de tempo é o receptor (padrão: 300 s).
 */

/** Chaves públicas aceitas: mapa keyId → PEM, lista `{ keyId, publicKey }` ou um PEM só. */
export type WebhookPublicKeys =
  | string
  | Record<string, string>
  | ReadonlyArray<{ keyId: string; publicKey: string }>

export type HeadersLike =
  | Headers
  | Record<string, string | string[] | undefined>

export interface VerifyOptions {
  /** Tolerância do timestamp, em segundos. Padrão 300. `0` desliga (não recomendado). */
  toleranceSeconds?: number
  /** Relógio de referência (teste). */
  now?: Date | number
}

export type WebhookFailure =
  | 'MISSING_HEADERS'
  | 'TIMESTAMP_INVALID'
  | 'TIMESTAMP_OUT_OF_TOLERANCE'
  | 'UNKNOWN_KEY_ID'
  | 'UNSUPPORTED_SIGNATURE_VERSION'
  | 'INVALID_SIGNATURE'

const MESSAGES: Record<WebhookFailure, string> = {
  MISSING_HEADERS: 'Faltam headers x-webhook-id, x-webhook-timestamp, x-webhook-key-id ou x-webhook-signature',
  TIMESTAMP_INVALID: 'x-webhook-timestamp não é uma data ISO 8601',
  TIMESTAMP_OUT_OF_TOLERANCE: 'Entrega fora da tolerância de tempo (possível replay)',
  UNKNOWN_KEY_ID: 'Nenhuma chave pública para este x-webhook-key-id',
  UNSUPPORTED_SIGNATURE_VERSION: 'Versão de assinatura não suportada (esperado v1=)',
  INVALID_SIGNATURE: 'Assinatura inválida',
}

function header(headers: HeadersLike, name: string): string | undefined {
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name) ?? undefined
  const rec = headers as Record<string, string | string[] | undefined>
  let v = rec[name]
  if (v === undefined) {
    const key = Object.keys(rec).find((k) => k.toLowerCase() === name)
    v = key ? rec[key] : undefined
  }
  return Array.isArray(v) ? v[0] : v
}

const keyCache = new Map<string, KeyObject>()
function keyFor(keys: WebhookPublicKeys, keyId: string): KeyObject | null {
  let pem: string | undefined
  if (typeof keys === 'string') pem = keys
  else if (Array.isArray(keys)) pem = keys.find((k) => k.keyId === keyId)?.publicKey
  else pem = Object.prototype.hasOwnProperty.call(keys, keyId) ? (keys as Record<string, string>)[keyId] : undefined
  if (!pem) return null
  let k = keyCache.get(pem)
  if (!k) {
    k = createPublicKey(pem)
    keyCache.set(pem, k)
  }
  return k
}

function toBytes(raw: string | Uint8Array): Buffer {
  return typeof raw === 'string' ? Buffer.from(raw, 'utf8') : Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength)
}

/** Diagnóstico: `null` se válida; senão o motivo. */
export function checkWebhook(rawBody: string | Uint8Array, headers: HeadersLike, keys: WebhookPublicKeys, opts: VerifyOptions = {}): WebhookFailure | null {
  const id = header(headers, 'x-webhook-id')
  const timestamp = header(headers, 'x-webhook-timestamp')
  const keyId = header(headers, 'x-webhook-key-id')
  const signature = header(headers, 'x-webhook-signature')
  if (!id || !timestamp || !keyId || !signature) return 'MISSING_HEADERS'

  const sentAt = Date.parse(timestamp)
  if (!Number.isFinite(sentAt)) return 'TIMESTAMP_INVALID'
  const tolerance = opts.toleranceSeconds ?? 300
  const now = opts.now === undefined ? Date.now() : typeof opts.now === 'number' ? opts.now : opts.now.getTime()
  if (tolerance > 0 && Math.abs(now - sentAt) > tolerance * 1000) return 'TIMESTAMP_OUT_OF_TOLERANCE'

  const key = keyFor(keys, keyId)
  if (!key) return 'UNKNOWN_KEY_ID'

  if (!signature.startsWith('v1=')) return 'UNSUPPORTED_SIGNATURE_VERSION'
  const sig = Buffer.from(signature.slice(3), 'base64')
  const message = Buffer.concat([Buffer.from(`${id}\n${timestamp}\n`, 'utf8'), toBytes(rawBody)])
  let ok = false
  try {
    ok = cryptoVerify('sha256', message, key, sig)
  } catch {
    ok = false
  }
  return ok ? null : 'INVALID_SIGNATURE'
}

/** `true` se a entrega é autêntica e está dentro da tolerância. Nunca lança por assinatura. */
export function verify(rawBody: string | Uint8Array, headers: HeadersLike, keys: WebhookPublicKeys, opts?: VerifyOptions): boolean {
  return checkWebhook(rawBody, headers, keys, opts) === null
}

/**
 * Verifica e devolve o evento. Lança `WebhookVerificationError` (com `code` = motivo) se não for
 * autêntico. Passe o CORPO CRU — reserializar o JSON muda os bytes e invalida a assinatura.
 */
export function constructEvent<T = Record<string, unknown>>(
  rawBody: string | Uint8Array,
  headers: HeadersLike,
  keys: WebhookPublicKeys,
  opts?: VerifyOptions
): WebhookEvent<T> {
  const failure = checkWebhook(rawBody, headers, keys, opts)
  if (failure) throw new WebhookVerificationError(MESSAGES[failure], { status: 400, code: failure })
  const text = typeof rawBody === 'string' ? rawBody : toBytes(rawBody).toString('utf8')
  try {
    return JSON.parse(text) as WebhookEvent<T>
  } catch {
    throw new WebhookVerificationError('Corpo do webhook não é JSON', { status: 400, code: 'INVALID_JSON' })
  }
}
