import { createPublicKey, verify as cryptoVerify } from 'node:crypto'
import type { EvidenceKey, EvidenceSignature } from './types'

/**
 * OFFLINE verification of the signed evidence, without depending on Catalisa
 * (`src/biometrics/services/evidence-signature.service.ts`):
 *
 *   message   = `${sessionId}|${attempt}|${bundleHash}|${signedAt}`
 *   signature = Ed25519 (RFC 8032) with the organization's key, base64
 *   key       = `GET /evidence-keys` → `publicKeyPem` of the signature's `keyId` (retired keys stay published)
 *
 * `attempt` is the session envelope's `attempt` (`GET /sessions/:id`).
 */
export function evidenceMessage(sessionId: string, attempt: number, bundleHash: string, signedAt: string): string {
  return `${sessionId}|${attempt}|${bundleHash}|${signedAt}`
}

export interface EvidenceToVerify {
  sessionId: string
  attempt: number
  bundleHash: string
  signature: EvidenceSignature
}

export interface OfflineVerification {
  valid: boolean
  keyId: string
  /** `true` when no published key has this `keyId`. */
  unknownKey: boolean
  retiredAt: string | null
}

export function verifyEvidenceSignature(ev: EvidenceToVerify, keys: ReadonlyArray<EvidenceKey> | Record<string, string>): OfflineVerification {
  const keyId = ev.signature.keyId
  const list: EvidenceKey[] = Array.isArray(keys)
    ? (keys as EvidenceKey[])
    : Object.entries(keys as Record<string, string>).map(([k, pem]) => ({ keyId: k, publicKeyPem: pem, createdAt: '', retiredAt: null }))
  const key = list.find((k) => k.keyId === keyId)
  if (!key) return { valid: false, keyId, unknownKey: true, retiredAt: null }
  if (ev.signature.alg !== 'Ed25519') return { valid: false, keyId, unknownKey: false, retiredAt: key.retiredAt }
  let valid = false
  try {
    valid = cryptoVerify(
      null,
      Buffer.from(evidenceMessage(ev.sessionId, ev.attempt, ev.bundleHash, ev.signature.signedAt), 'utf8'),
      createPublicKey(key.publicKeyPem),
      Buffer.from(ev.signature.value, 'base64')
    )
  } catch {
    valid = false
  }
  return { valid, keyId, unknownKey: false, retiredAt: key.retiredAt }
}
