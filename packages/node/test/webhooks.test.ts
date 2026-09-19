import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { generateKeyPairSync, createSign } from 'node:crypto'
import { Biometrics, WebhookVerificationError, checkWebhook, constructEvent, verifyWebhook } from '../src'

// Vetor produzido pelo CÓDIGO DO BB (scripts/gen-vectors.bb.ts rodando src/webhooks-engine/utils/crypto.ts).
const vectors = JSON.parse(readFileSync(new URL('../../../vectors/vectors.json', import.meta.url), 'utf8'))
const w = vectors.webhook as { keys: Record<string, string>; headers: Record<string, string>; body: string; tamperedBody: string; now: string }
const now = new Date(w.now)

describe('webhooks.verify — vetor gerado pelo BB', () => {
  it('aceita a entrega assinada pelo Webhooks Engine', () => {
    expect(verifyWebhook(w.body, w.headers, w.keys, { now })).toBe(true)
  })

  it('aceita o corpo como Buffer/Uint8Array (bytes crus)', () => {
    expect(verifyWebhook(Buffer.from(w.body, 'utf8'), w.headers, w.keys, { now })).toBe(true)
    expect(verifyWebhook(new TextEncoder().encode(w.body), w.headers, w.keys, { now })).toBe(true)
  })

  it('aceita objeto Headers e nomes com caixa diferente', () => {
    const h = new Headers(w.headers)
    expect(verifyWebhook(w.body, h, w.keys, { now })).toBe(true)
    const upper = Object.fromEntries(Object.entries(w.headers).map(([k, v]) => [k.toUpperCase(), v]))
    expect(verifyWebhook(w.body, upper, w.keys, { now })).toBe(true)
  })

  it('aceita a chave como PEM único e como lista { keyId, publicKey } (formato de GET /subscriptions/:id/keys)', () => {
    const [keyId, pem] = Object.entries(w.keys)[0]
    expect(verifyWebhook(w.body, w.headers, pem, { now })).toBe(true)
    expect(verifyWebhook(w.body, w.headers, [{ keyId, publicKey: pem }], { now })).toBe(true)
  })

  it('recusa corpo adulterado', () => {
    expect(checkWebhook(w.tamperedBody, w.headers, w.keys, { now })).toBe('INVALID_SIGNATURE')
  })

  it('recusa corpo reserializado (espaços mudam os bytes)', () => {
    const reserialized = JSON.stringify(JSON.parse(w.body), null, 2)
    expect(verifyWebhook(reserialized, w.headers, w.keys, { now })).toBe(false)
  })

  it('recusa id ou timestamp trocados (fazem parte da mensagem assinada)', () => {
    expect(checkWebhook(w.body, { ...w.headers, 'x-webhook-id': 'msg_outro' }, w.keys, { now })).toBe('INVALID_SIGNATURE')
    const ts = '2026-09-18T15:00:01.000Z'
    expect(checkWebhook(w.body, { ...w.headers, 'x-webhook-timestamp': ts }, w.keys, { now })).toBe('INVALID_SIGNATURE')
  })

  it('aplica a tolerância de tempo (padrão 300 s), nos dois sentidos', () => {
    const sent = Date.parse(w.headers['x-webhook-timestamp'])
    expect(verifyWebhook(w.body, w.headers, w.keys, { now: sent + 299_000 })).toBe(true)
    expect(checkWebhook(w.body, w.headers, w.keys, { now: sent + 301_000 })).toBe('TIMESTAMP_OUT_OF_TOLERANCE')
    expect(checkWebhook(w.body, w.headers, w.keys, { now: sent - 301_000 })).toBe('TIMESTAMP_OUT_OF_TOLERANCE')
    expect(verifyWebhook(w.body, w.headers, w.keys, { now: sent + 3_600_000, toleranceSeconds: 3601 })).toBe(true)
  })

  it('recusa keyId desconhecido, versão diferente de v1 e headers ausentes', () => {
    expect(checkWebhook(w.body, { ...w.headers, 'x-webhook-key-id': 'whk_outra' }, w.keys, { now })).toBe('UNKNOWN_KEY_ID')
    const sig = w.headers['x-webhook-signature'].replace(/^v1=/, 'v2=')
    expect(checkWebhook(w.body, { ...w.headers, 'x-webhook-signature': sig }, w.keys, { now })).toBe('UNSUPPORTED_SIGNATURE_VERSION')
    const { 'x-webhook-signature': _omit, ...semAssinatura } = w.headers
    expect(checkWebhook(w.body, semAssinatura, w.keys, { now })).toBe('MISSING_HEADERS')
    expect(checkWebhook(w.body, { ...w.headers, 'x-webhook-timestamp': 'ontem' }, w.keys, { now })).toBe('TIMESTAMP_INVALID')
  })

  it('recusa assinatura válida de OUTRA chave com o mesmo keyId', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const s = createSign('RSA-SHA256')
    s.update(`${w.headers['x-webhook-id']}\n${w.headers['x-webhook-timestamp']}\n${w.body}`)
    const forged = `v1=${s.sign(privateKey, 'base64')}`
    expect(verifyWebhook(w.body, { ...w.headers, 'x-webhook-signature': forged }, w.keys, { now })).toBe(false)
  })

  it('assinatura base64 lixo não lança', () => {
    expect(verifyWebhook(w.body, { ...w.headers, 'x-webhook-signature': 'v1=@@@' }, w.keys, { now })).toBe(false)
  })
})

describe('webhooks.constructEvent', () => {
  it('devolve o evento tipado quando válido', () => {
    const ev = constructEvent<{ sessionId: string; outcome: string }>(w.body, w.headers, w.keys, { now })
    expect(ev.type).toBe('biometrics.session.completed')
    expect(ev.data.outcome).toBe('APPROVED')
    expect(ev.id).toMatch(/^evt_/)
    expect(ev.metadata.organizationId).toBe('b0000000-0000-0000-0000-000000000001')
  })

  it('lança WebhookVerificationError com code', () => {
    try {
      constructEvent(w.tamperedBody, w.headers, w.keys, { now })
      expect.unreachable()
    } catch (e) {
      expect(e).toBeInstanceOf(WebhookVerificationError)
      expect((e as WebhookVerificationError).code).toBe('INVALID_SIGNATURE')
      expect((e as WebhookVerificationError).status).toBe(400)
    }
  })

  it('também está disponível como Biometrics.webhooks e na instância', () => {
    expect(Biometrics.webhooks.verify(w.body, w.headers, w.keys, { now })).toBe(true)
    const b = new Biometrics({ apiKey: 'k', fetch: async () => new Response('{}') })
    expect(b.webhooks.constructEvent(w.body, w.headers, w.keys, { now }).id).toMatch(/^evt_/)
  })
})
