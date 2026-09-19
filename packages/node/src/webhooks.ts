import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { WebhookVerificationError } from './errors'
import type { WebhookEvent } from './types'

/**
 * Verification of Catalisa Webhooks Engine deliveries, exactly as the engine signs them
 * (`src/webhooks-engine/utils/crypto.ts` and `services/signing-key.service.ts`):
 *
 *   message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
 *   signature = RSA-SHA256 (PKCS#1 v1.5) with the subscription's private key, base64
 *   header    = x-webhook-signature: "v1=<base64>"; x-webhook-key-id selects the public key
 *
 * The signature is ASYMMETRIC: you verify with the subscription's PUBLIC key
 * (`GET /webhooks-engine/api/v1/subscriptions/:id/keys`), not with a shared secret.
 * The server does not reject old deliveries — the receiver enforces the time tolerance (default 300 s).
 */

/** Accepted public keys: keyId → PEM map, `{ keyId, publicKey }` list, or a single PEM. */
export type WebhookPublicKeys =
  | string
  | Record<string, string>
  | ReadonlyArray<{ keyId: string; publicKey: string }>

export type HeadersLike =
  | Headers
  | Record<string, string | string[] | undefined>

export interface VerifyOptions {
  /** Timestamp tolerance in seconds. Default 300. `0` disables it (not recommended). */
  toleranceSeconds?: number
  /** Reference clock (tests). */
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
  MISSING_HEADERS: 'Missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature header',
  TIMESTAMP_INVALID: 'x-webhook-timestamp is not an ISO 8601 date',
  TIMESTAMP_OUT_OF_TOLERANCE: 'Delivery is outside the time tolerance (possible replay)',
  UNKNOWN_KEY_ID: 'No public key for this x-webhook-key-id',
  UNSUPPORTED_SIGNATURE_VERSION: 'Unsupported signature version (expected v1=)',
  INVALID_SIGNATURE: 'Invalid signature',
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

/** Diagnostics: `null` when valid; otherwise the failure reason. */
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

/** `true` when the delivery is authentic and within tolerance. Never throws on bad signatures. */
export function verify(rawBody: string | Uint8Array, headers: HeadersLike, keys: WebhookPublicKeys, opts?: VerifyOptions): boolean {
  return checkWebhook(rawBody, headers, keys, opts) === null
}

/**
 * Verifies and returns the event. Throws `WebhookVerificationError` (with `code` = reason) when it
 * is not authentic. Pass the RAW body — re-serializing the JSON changes the bytes and breaks the signature.
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
    throw new WebhookVerificationError('Webhook body is not JSON', { status: 400, code: 'INVALID_JSON' })
  }
}
