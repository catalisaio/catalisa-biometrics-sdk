import { Biometrics, BiometricsError, QuotaExceededError, RateLimitError, SubaccountSuspendedError } from '@catalisa/biometrics'

const bio = new Biometrics({
  apiKey: process.env.CATALISA_API_KEY,
  baseUrl: process.env.CATALISA_BIOMETRICS_URL,
  subaccountId: process.env.CATALISA_SUBACCOUNT_ID, // organization key acting on behalf of the subaccount
})

try {
  const session = await bio.sessions.create({ flow: 'LIVENESS_ONLY', purpose: 'abertura de conta' })
  console.log('ok:', session.handoff.captureUrl)
} catch (e) {
  if (e instanceof QuotaExceededError) {
    // 402: do not open sessions; notify the subaccount's customer or raise the quota
    console.log(`blocked: ${e.code} — monthly quota used (${e.details.used}/${e.details.monthlyQuota})`)
  } else if (e instanceof SubaccountSuspendedError) {
    // 403: the organization suspended this subaccount
    console.log(`blocked: ${e.code} — subaccount suspended`)
  } else if (e instanceof RateLimitError) {
    console.log(`rate limited; retry in ${e.retryAfter ?? 1} s`) // the SDK already retried
  } else if (e instanceof BiometricsError) {
    console.error(`error ${e.status}: ${e.code} (requestId ${e.requestId})`)
    process.exitCode = 1
  } else throw e
}
