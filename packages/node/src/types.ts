/**
 * Tipos do contrato de fio do Catalisa Biometrics.
 *
 * Espelham `src/biometrics/types/index.ts` do building block (origin/main). Unions de
 * string ficam abertas (`| (string & {})`) onde o BB declara o vocabulário como aditivo:
 * um valor novo no servidor não quebra a compilação de quem já integrou.
 */

type Open<T extends string> = T | (string & {})

export type BiometricsFlow = 'ONBOARDING' | 'AUTHENTICATION' | 'ENROLLMENT' | 'LIVENESS_ONLY' | 'DEDUP'

export type SessionStatus =
  | 'SESSION_OPEN'
  | 'PROCESSING'
  | 'APPROVED'
  | 'REJECTED'
  | 'INCONCLUSIVE'
  | 'RETRY_ALLOWED'
  | 'EXPIRED'
  | 'CANCELLED'
  | 'ERROR'

/** Status em que a sessão não muda mais. */
export const TERMINAL_STATUSES: readonly SessionStatus[] = ['APPROVED', 'REJECTED', 'INCONCLUSIVE', 'EXPIRED', 'CANCELLED']

export type ProviderType = Open<'OPENSOURCE' | 'MOCK' | 'SERPRO_DATAVALID' | 'FACETEC' | 'UNICO'>
export type Assurance = 'BASIC' | 'ENHANCED' | 'CERTIFIED'
export type CaptureMode = Open<'RAW_FRAMES' | 'PROVIDER_SDK' | 'PROVIDER_HOSTED'>
export type CaptureChannel = Open<'HOSTED' | 'IFRAME' | 'WIDGET' | 'SDK'>
export type ReferenceSource = 'DOCUMENT_IMAGE' | 'FILE' | 'ENROLLED_TEMPLATE' | 'PROVIDER_BASE'

export type Gesture = Open<
  | 'TURN_LEFT'
  | 'TURN_RIGHT'
  | 'BLINK'
  | 'SMILE'
  | 'OPEN_MOUTH'
  | 'NOD'
  | 'APPROACH'
  | 'TILT_LEFT'
  | 'TILT_RIGHT'
  | 'EYEBROWS_RAISE'
>

export type CheckKind = Open<
  'quality.capture' | 'liveness.passive' | 'liveness.active' | 'capture.integrity' | 'identity.continuity' | 'match.1_1'
>
export type CheckStatus = 'PASSED' | 'FAILED' | 'INCONCLUSIVE' | 'SKIPPED'

/** Vocabulário fechado e aditivo de motivos da decisão. */
export type Reason = Open<
  | 'quality.no_face'
  | 'quality.multiple_faces'
  | 'quality.face_too_small'
  | 'quality.too_dark'
  | 'quality.blur'
  | 'quality.occlusion'
  | 'liveness.passive.failed'
  | 'liveness.active.gesture_missing'
  | 'liveness.active.out_of_order'
  | 'liveness.active.timeout'
  | 'liveness.active.flat_surface_suspected'
  | 'capture.injection_suspected'
  | 'capture.virtual_camera_suspected'
  | 'capture.device_changed'
  | 'capture.replay_suspected'
  | 'capture.telemetry_missing'
  | 'identity.continuity_broken'
  | 'match.below_threshold'
  | 'match.gray_zone'
  | 'match.reference_unusable'
  | 'match.template_model_mismatch'
  | 'provider.not_supported'
  | 'provider.error'
  | 'policy.assurance_insufficient'
  | 'policy.capture_channel_not_allowed'
  | 'policy.max_attempts_reached'
  | 'subject.locked'
>

export interface CheckEngine {
  name: string
  model: string
  version: string
}

export interface Check {
  kind: CheckKind
  status: CheckStatus
  score: number
  threshold: number
  reasons: Reason[]
  engine: CheckEngine
  details?: Record<string, unknown>
}

export interface Decision {
  outcome: SessionStatus
  reasons: Reason[]
  policyId: string
  reviewRequired: boolean
  policyOverride: string | null
}

export interface EvidenceArtifact {
  kind: Open<'best_frame' | 'challenge_video' | 'reference' | 'reference_portrait'>
  fileId: string | null
  hash: string
  contentType: string
}

export interface EvidenceSignature {
  alg: 'Ed25519'
  keyId: string
  signedAt: string
  /** Assinatura em base64 sobre `${sessionId}|${attempt}|${bundleHash}|${signedAt}`. */
  value: string
}

export interface Evidence {
  bundleHash: string
  artifacts: EvidenceArtifact[]
  client: { ipHash: string | null; userAgent: string | null; captureTelemetryHash: string | null }
  policySnapshotHash: string
  retainedUntil: string | null
  signature?: EvidenceSignature | null
  [extra: string]: unknown
}

/** `GET /sessions/:id/evidence`: a evidência mais URLs temporárias de download dos artefatos. */
export interface EvidenceWithUrls extends Evidence {
  urls: Record<string, { url: string; expiresAt: string } | null>
}

export interface Handoff {
  /** URL da página de captura hospedada. É o que se abre no navegador/iframe/WebView. */
  captureUrl: string
  /** Token de uso único por tentativa. Só para captura própria (`POST /sessions/:id/captures`). */
  captureToken: string
  captureMode: CaptureMode
  challenge?: { script: Gesture[]; timeoutMs: number; perGestureMs: number; slotsMs?: number[] }
  provider?: Record<string, unknown>
  expiresAt: string
}

export interface EvaluationConformance {
  profileId: string
  label: string
  standard: string
  conforms: boolean
  certified: boolean
  violations: string[]
}

export interface SessionEnvelope {
  sessionId: string
  modality: 'face'
  flow: BiometricsFlow
  provider: ProviderType
  assurance: Assurance
  evaluation: EvaluationConformance | null
  status: SessionStatus
  attempt: number
  maxAttempts: number
  subjectRef: { type: 'CPF'; hmac: string; masked: string } | null
  customerId: string | null
  purpose: string
  reference: {
    source: ReferenceSource | null
    fileId: string | null
    templateId: string | null
    portraitExtracted: boolean
    document: { authenticity: string; mrz: Record<string, unknown> | null; qr: Record<string, unknown> | null } | null
  } | null
  capture: { channel: CaptureChannel | null; embedHost: string | null } | null
  metadata: Record<string, string> | null
  enrollment: { templateId: string } | null
  decision: Decision | null
  checks: Check[]
  /** Presente na criação (e em nova tentativa). */
  handoff?: Handoff
  evidence: Evidence | null
  cost: { amount: string; currency: string; estimated: boolean }
  raw: unknown
  createdAt: string
  capturedAt: string | null
  evaluatedAt: string | null
  expiresAt: string
  elapsedMs: number | null
  /** Subcontas: presente quando o BB tem subcontas; `null` = sessão da organização. */
  subaccountId?: string | null
}

/** Envelope devolvido pela criação: `handoff` sempre presente. */
export type CreatedSession = SessionEnvelope & { handoff: Handoff }

export interface Appearance {
  colors?: { primary?: string; background?: string; surface?: string; text?: string; danger?: string }
  radius?: number
  font?: { family?: 'system' | 'inter' | 'roboto' | 'open-sans' | 'lato' | 'montserrat' | 'source-sans' }
  logoFileId?: string
  mode?: 'light' | 'dark' | 'auto'
  layout?: 'card' | 'fullscreen' | 'minimal'
  texts?: Record<string, Record<string, string>>
  poweredBy?: boolean
  /** Para onde a página vai ao terminar. Em app nativo, é o sinal de "acabou" para fechar a WebView. */
  redirectUrl?: string
}

export type ReferenceInput =
  | { source: 'DOCUMENT_IMAGE'; fileId: string }
  | { source: 'FILE'; fileId: string }
  | { source: 'ENROLLED_TEMPLATE'; templateId: string }
  | { source: 'PROVIDER_BASE' }

export interface CreateSessionParams {
  flow: Exclude<BiometricsFlow, 'DEDUP'> | 'DEDUP'
  /** Finalidade, de 3 a 120 caracteres. Vai para a trilha. */
  purpose: string
  legalBasis?: string
  subjectRef?: { type: 'CPF'; value: string }
  customerId?: string
  reference?: ReferenceInput
  providerConfigId?: string
  appearance?: Appearance
  /** Só para teste e calibração; em produção o BB sorteia. */
  challengeScript?: Gesture[]
  /** Até 10 rótulos livres. Nunca CPF. */
  metadata?: Record<string, string>
  /** Grava o cadastro facial ao aprovar. Só ONBOARDING e ENROLLMENT. */
  enrollOnApprove?: boolean
}

export interface ListSessionsParams {
  page?: number
  pageSize?: number
  status?: SessionStatus
  flow?: BiometricsFlow
  customerId?: string
  /** Filtra pelo CPF do titular (o BB calcula o HMAC). Vai na query string: prefira `customerId` quando puder. */
  subjectCpf?: string
  from?: string | Date
  to?: string | Date
  /** Subcontas: filtra por subconta quando a chave é da organização. */
  subaccountId?: string
}

export interface SessionList {
  data: SessionEnvelope[]
  meta: { total: number; page: { number: number; size: number } }
}

export interface EvidenceKey {
  keyId: string
  publicKeyPem: string
  createdAt: string
  retiredAt: string | null
}

export interface EvidenceVerification {
  valid: boolean
  keyId: string
  retiredAt: string | null
}

/** Corpo de toda entrega de webhook (Webhooks Engine). */
export interface WebhookEvent<T = Record<string, unknown>> {
  /** Identificador ESTÁVEL do evento. Use para idempotência. */
  id: string
  type: BiometricsEventType
  data: T
  metadata: { timestamp: string; correlationId?: string; organizationId?: string }
}

export type BiometricsEventType = Open<
  | 'biometrics.session.created'
  | 'biometrics.session.completed'
  | 'biometrics.session.review_required'
  | 'biometrics.session.expired'
  | 'biometrics.subject.locked'
  | 'biometrics.subject.erased'
  | 'biometrics.enrollment.created'
  | 'biometrics.enrollment.revoked'
  | 'biometrics.usage.recorded'
>

/** `data` de `biometrics.session.completed` e `.review_required`. */
export interface SessionCompletedData {
  sessionId: string
  organizationId: string
  flow: BiometricsFlow
  provider: ProviderType
  outcome: SessionStatus
  reasons: Reason[]
  customerId: string | null
  subjectHmac: string | null
  modelVersion: string
  subaccountId?: string | null
}
