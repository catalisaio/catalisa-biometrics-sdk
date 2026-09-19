// npm install @catalisa/biometrics
import { Biometrics } from '@catalisa/biometrics'

const bio = new Biometrics({
  apiKey: process.env.CATALISA_API_KEY,
  baseUrl: process.env.CATALISA_BIOMETRICS_URL, // optional; default: https://api.biometrics.catalisa.app/v1
})

const session = await bio.sessions.create({
  flow: 'LIVENESS_ONLY',
  purpose: 'abertura de conta',
  metadata: { orderId: '123' },
})

console.log('sessionId:', session.sessionId)
console.log('captureUrl:', session.handoff.captureUrl) // send the person here (link, iframe or WebView)
