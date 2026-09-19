// Gera vetores de teste usando o CÓDIGO DO BB (origin/main), sem alterá-lo.
import 'reflect-metadata'
import { randomBytes, randomUUID } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { generateKeyPair, generateKeyId, createSignaturePayload, signPayload, verifySignature } from '@webhooks-engine/utils/crypto'
import { BiometricsEvidenceSignatureService } from '@biometrics/services/evidence-signature.service'

process.env.BIOMETRICS_CREDENTIAL_MASTER_KEY ??= randomBytes(32).toString('hex')

const mode = process.argv[2] ?? 'static'
const out = process.argv[3]

async function webhookDelivery(timestamp: string, keys?: { publicKey: string; privateKey: string; keyId: string }) {
  const k = keys ?? { ...(await generateKeyPair()), keyId: generateKeyId() }
  const orgId = 'b0000000-0000-0000-0000-000000000001'
  // Mesma forma do WebhookDeliveryPayload montado pelo webhook-consumer, com o payload de publishTerminal (capture.service)
  const event = {
    id: 'evt_' + randomUUID().replace(/-/g, '').slice(0, 20),
    type: 'biometrics.session.completed',
    data: {
      sessionId: '5b0e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b',
      organizationId: orgId,
      flow: 'LIVENESS_ONLY',
      provider: 'OPENSOURCE',
      outcome: 'APPROVED',
      reasons: [],
      customerId: null,
      subjectHmac: null,
      modelVersion: 'face-engine-2026.09.20',
      subaccountId: null,
      nota: 'acentuação e emoji não: ção',
    },
    metadata: { timestamp, organizationId: orgId },
  }
  const messageId = `msg_${randomUUID().replace(/-/g, '')}`
  const body = JSON.stringify(event) // delivery.service: body = JSON.stringify(event)
  const signature = signPayload(createSignaturePayload(messageId, timestamp, body), k.privateKey)
  if (!verifySignature(createSignaturePayload(messageId, timestamp, body), signature, k.publicKey)) throw new Error('auto-verificação falhou')
  const headers = {
    'x-webhook-id': messageId,
    'x-webhook-timestamp': timestamp,
    'x-webhook-signature': `v1=${signature}`,
    'x-webhook-key-id': k.keyId,
    'x-webhook-version': 'v1',
  }
  return { keys: { [k.keyId]: k.publicKey }, headers, body, _private: k.privateKey }
}

async function evidence() {
  const store: any[] = []
  const repo: any = {
    findActive: async () => store.find((k) => !k.retiredAt) ?? null,
    create: async (d: any) => { const e = { ...d, id: randomUUID(), createdAt: new Date('2026-09-18T12:00:00.000Z'), retiredAt: null }; store.push(e); return e },
    findByKeyId: async (keyId: string) => store.find((k) => k.keyId === keyId) ?? null,
    listByOrganization: async () => store,
    retire: async () => {},
  }
  const svc = new BiometricsEvidenceSignatureService(repo)
  const sessionId = '5b0e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b'
  const attempt = 1
  const bundleHash = 'a3f1c2d4e5b60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff'
  const sig = await svc.sign('b0000000-0000-0000-0000-000000000001', sessionId, attempt, bundleHash)
  if (sig.isErr()) throw new Error(sig.error.message)
  const v = await svc.verify(sessionId, attempt, bundleHash, sig.value)
  if (v.isErr() || !v.value.valid) throw new Error('verify do BB falhou')
  const keys = await svc.publicKeys('b0000000-0000-0000-0000-000000000001')
  if (keys.isErr()) throw new Error('keys')
  return {
    evidenceKeysResponse: { data: keys.value, meta: { alg: 'Ed25519', message: '${sessionId}|${attempt}|${bundleHash}|${signedAt}' } },
    sessionId, attempt,
    evidence: { bundleHash, signature: sig.value },
  }
}

if (mode === 'static') {
  const w = await webhookDelivery('2026-09-18T15:00:00.000Z')
  const { _private, ...pub } = w
  // negativo: corpo adulterado (outcome) com os mesmos headers
  const tampered = w.body.replace('"APPROVED"', '"REJECTED"')
  const e = await evidence()
  const vectors = {
    generatedBy: 'building-blocks-v2 origin/main — src/webhooks-engine/utils/crypto.ts (generateKeyPair, createSignaturePayload, signPayload) e src/biometrics/services/evidence-signature.service.ts (sign/publicKeys)',
    webhook: { ...pub, now: '2026-09-18T15:01:00.000Z', tamperedBody: tampered },
    evidence: e,
  }
  writeFileSync(out!, JSON.stringify(vectors, null, 2) + '\n')
  console.log('ok static', out)
} else {
  // fresh: timestamp = agora, para os servidores de snippet com tolerância real
  const w = await webhookDelivery(new Date().toISOString())
  const { _private, ...pub } = w
  writeFileSync(out!, JSON.stringify({ ...pub, tamperedBody: w.body.replace('"APPROVED"', '"REJECTED"') }, null, 2))
  console.log('ok fresh', out)
}
