// Generates test vectors with the BUILDING BLOCK'S OWN CODE (origin/main), without modifying it.
// Runs INSIDE a copy of building-blocks-v2's src/ (see scripts/bb-vector.sh):
//   static <file> → vectors/vectors.json (fixed timestamp; RSA webhook + Ed25519 evidence)
//   fresh  <file> → a delivery signed NOW (+ a tampered one and a 10-minute-old one), for the snippet servers
import 'reflect-metadata'
import { randomBytes, randomUUID } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { generateKeyPair, generateKeyId, createSignaturePayload, signPayload, verifySignature } from '@webhooks-engine/utils/crypto'
import { BiometricsEvidenceSignatureService } from '@biometrics/services/evidence-signature.service'

process.env.BIOMETRICS_CREDENTIAL_MASTER_KEY ??= randomBytes(32).toString('hex')

const mode = process.argv[2] ?? 'static'
const out = process.argv[3]
const ORG_ID = 'b0000000-0000-0000-0000-000000000001'
const SESSION_ID = '5b0e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b'

type Keys = { publicKey: string; privateKey: string; keyId: string }

async function webhookDelivery(timestamp: string, keys?: Keys) {
  const k: Keys = keys ?? { ...(await generateKeyPair()), keyId: generateKeyId() }
  // Same shape as the WebhookDeliveryPayload built by webhook-consumer, with publishTerminal's payload (capture.service)
  const event = {
    id: 'evt_' + randomUUID().replace(/-/g, '').slice(0, 20),
    type: 'biometrics.session.completed',
    data: {
      sessionId: SESSION_ID,
      organizationId: ORG_ID,
      flow: 'LIVENESS_ONLY',
      provider: 'OPENSOURCE',
      outcome: 'APPROVED',
      reasons: [],
      customerId: null,
      subjectHmac: null,
      modelVersion: 'face-engine-2026.09.20',
      subaccountId: null,
      note: 'non-ASCII bytes: verificação concluída',
    },
    metadata: { timestamp, organizationId: ORG_ID },
  }
  const messageId = `msg_${randomUUID().replace(/-/g, '')}`
  const body = JSON.stringify(event) // delivery.service: body = JSON.stringify(event)
  const signature = signPayload(createSignaturePayload(messageId, timestamp, body), k.privateKey)
  if (!verifySignature(createSignaturePayload(messageId, timestamp, body), signature, k.publicKey)) throw new Error('self-check failed')
  const headers = {
    'x-webhook-id': messageId,
    'x-webhook-timestamp': timestamp,
    'x-webhook-signature': `v1=${signature}`,
    'x-webhook-key-id': k.keyId,
    'x-webhook-version': 'v1',
  }
  return { keys: { [k.keyId]: k.publicKey }, headers, body, privateKey: k.privateKey, keyId: k.keyId, publicKey: k.publicKey }
}

async function evidence() {
  // In-memory repository: the service code (key creation, encryption, signing) is the server's own.
  const store: any[] = []
  const repo: any = {
    findActive: async () => store.find((k) => !k.retiredAt) ?? null,
    create: async (d: any) => {
      const e = { ...d, id: randomUUID(), createdAt: new Date('2026-09-18T12:00:00.000Z'), retiredAt: null }
      store.push(e)
      return e
    },
    findByKeyId: async (keyId: string) => store.find((k) => k.keyId === keyId) ?? null,
    listByOrganization: async () => store,
    retire: async () => {},
  }
  const svc = new BiometricsEvidenceSignatureService(repo)
  const attempt = 1
  const bundleHash = 'a3f1c2d4e5b60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff'
  const sig = await svc.sign(ORG_ID, SESSION_ID, attempt, bundleHash)
  if (sig.isErr()) throw new Error(sig.error.message)
  const v = await svc.verify(SESSION_ID, attempt, bundleHash, sig.value)
  if (v.isErr() || !v.value.valid) throw new Error('server-side verify failed')
  const keys = await svc.publicKeys(ORG_ID)
  if (keys.isErr()) throw new Error('keys')
  return {
    evidenceKeysResponse: { data: keys.value, meta: { alg: 'Ed25519', message: '${sessionId}|${attempt}|${bundleHash}|${signedAt}' } },
    sessionId: SESSION_ID,
    attempt,
    evidence: { bundleHash, signature: sig.value },
  }
}

const tamper = (body: string) => body.replace('"APPROVED"', '"REJECTED"')

if (mode === 'static') {
  const w = await webhookDelivery('2026-09-18T15:00:00.000Z')
  const vectors = {
    generatedBy:
      'building-blocks-v2 origin/main — src/webhooks-engine/utils/crypto.ts (generateKeyPair, createSignaturePayload, signPayload) and src/biometrics/services/evidence-signature.service.ts (sign/publicKeys)',
    webhook: { keys: w.keys, headers: w.headers, body: w.body, now: '2026-09-18T15:01:00.000Z', tamperedBody: tamper(w.body) },
    evidence: await evidence(),
    // Every postMessage event name the hosted capture page emits (emit('<name>'...) in capture-page/page.ts)
    captureEvents: [...new Set([...readFileSync('src/biometrics/capture-page/page.ts', 'utf8').matchAll(/emit\((?:'([a-z:]+)'|STATE==='done'\?'done':'expired')/g)].flatMap((m) => (m[1] ? [m[1]] : ['done', 'expired'])))].sort(),
  }
  writeFileSync(out!, JSON.stringify(vectors, null, 2) + '\n')
  console.log('ok static', out)
} else {
  const w = await webhookDelivery(new Date().toISOString())
  // a delivery from 10 minutes ago, signed with the SAME key: must fail the 300 s tolerance
  const stale = await webhookDelivery(new Date(Date.now() - 600_000).toISOString(), { publicKey: w.publicKey, privateKey: w.privateKey, keyId: w.keyId })
  writeFileSync(out!, JSON.stringify({ keys: w.keys, headers: w.headers, body: w.body, tamperedBody: tamper(w.body), stale: { headers: stale.headers, body: stale.body } }, null, 2))
  console.log('ok fresh', out)
}
