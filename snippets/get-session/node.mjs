import { Biometrics, NotFoundError } from '@catalisa/biometrics'

const bio = new Biometrics({ apiKey: process.env.CATALISA_API_KEY, baseUrl: process.env.CATALISA_BIOMETRICS_URL })

try {
  const session = await bio.sessions.get(process.env.SESSION_ID)
  console.log('status:', session.status)
  if (session.decision) {
    console.log('decision:', session.decision.outcome, session.decision.reasons.join(', ') || '(no reasons)')
    for (const c of session.checks) console.log(` - ${c.kind}: ${c.status} (score ${c.score} / threshold ${c.threshold})`)
  }
} catch (e) {
  if (e instanceof NotFoundError) console.error('Session not found (or owned by another organization)')
  else throw e
}
