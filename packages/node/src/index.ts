export { Biometrics, type BiometricsOptions, type CallOptions, type CreateOptions, type CaptureSubmission } from './client'
export * from './errors'
export * from './types'
export { verifyEvidenceSignature, evidenceMessage, type EvidenceToVerify, type OfflineVerification } from './evidence'
export {
  verify as verifyWebhook,
  constructEvent,
  checkWebhook,
  type WebhookPublicKeys,
  type HeadersLike,
  type VerifyOptions,
  type WebhookFailure,
} from './webhooks'
export { DEFAULT_BASE_URL, SDK_VERSION, type FetchLike } from './http'
export { Biometrics as default } from './client'
