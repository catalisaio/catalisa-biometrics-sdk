import { createPublicKey, verify as cryptoVerify } from 'node:crypto'
import type { EvidenceKey, EvidenceSignature } from './types'

/**
 * Verificação OFFLINE da evidência assinada, sem depender da Catalisa
 * (`src/biometrics/services/evidence-signature.service.ts`):
 *
 *   mensagem   = `${sessionId}|${attempt}|${bundleHash}|${signedAt}`
 *   assinatura = Ed25519 (RFC 8032) com a chave da organização, em base64
 *   chave      = `GET /evidence-keys` → `publicKeyPem` do `keyId` da assinatura (chaves aposentadas continuam publicadas)
 *
 * `attempt` é o `attempt` do envelope da sessão (`GET /sessions/:id`).
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
  /** `true` se não há chave publicada com esse `keyId`. */
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
