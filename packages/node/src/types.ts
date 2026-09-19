/**
 * Wire-contract types of Catalisa Biometrics.
 *
 * They mirror `src/biometrics/types/index.ts` of the building block (origin/main). String
 * unions stay open (`| (string & {})`) where the server declares the vocabulary as additive:
 * a new server-side value does not break the build of an existing integration.
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

/** Statuses after which a session never changes again. */
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

/** Closed, additive vocabulary of decision reasons. */
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
  /** Base64 signature over `${sessionId}|${attempt}|${bundleHash}|${signedAt}`. */
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

/** `GET /sessions/:id/evidence`: the evidence plus short-lived download URLs for the artifacts. */
export interface EvidenceWithUrls extends Evidence {
  urls: Record<string, { url: string; expiresAt: string } | null>
}

export interface Handoff {
  /** Hosted capture page URL. Open it in a browser tab, iframe or WebView. */
  captureUrl: string
  /** Single-use, per-attempt token. Only for custom capture (`POST /sessions/:id/captures`). */
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
  /** Present on creation (and on a new attempt). */
  handoff?: Handoff
  evidence: Evidence | null
  cost: { amount: string; currency: string; estimated: boolean }
  raw: unknown
  createdAt: string
  capturedAt: string | null
  evaluatedAt: string | null
  expiresAt: string
  elapsedMs: number | null
  /** Subaccounts: present when the server supports subaccounts; `null` = organization-level session. */
  subaccountId?: string | null
}

/** Envelope returned on creation: `handoff` is always present. */
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
  /** Where the page navigates when finished. In native apps this is the "done" signal to close the WebView. */
  redirectUrl?: string
}

export type ReferenceInput =
  | { source: 'DOCUMENT_IMAGE'; fileId: string }
  | { source: 'FILE'; fileId: string }
  | { source: 'ENROLLED_TEMPLATE'; templateId: string }
  | { source: 'PROVIDER_BASE' }

export interface CreateSessionParams {
  flow: Exclude<BiometricsFlow, 'DEDUP'> | 'DEDUP'
  /** Purpose, 3 to 120 characters. Recorded in the audit trail. */
  purpose: string
  legalBasis?: string
  subjectRef?: { type: 'CPF'; value: string }
  customerId?: string
  reference?: ReferenceInput
  providerConfigId?: string
  appearance?: Appearance
  /** Testing and calibration only; in production the server draws the gestures. */
  challengeScript?: Gesture[]
  /** Up to 10 free-form labels. Never a CPF. */
  metadata?: Record<string, string>
  /** Stores the face template on approval. ONBOARDING and ENROLLMENT only. */
  enrollOnApprove?: boolean
}

export interface ListSessionsParams {
  page?: number
  pageSize?: number
  status?: SessionStatus
  flow?: BiometricsFlow
  customerId?: string
  /** Filters by the subject's CPF (the server computes the HMAC). Goes in the query string: prefer `customerId` when you can. */
  subjectCpf?: string
  from?: string | Date
  to?: string | Date
  /** Subaccounts: filter by subaccount when using an organization key. */
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

/** Body of every webhook delivery (Webhooks Engine). */
export interface WebhookEvent<T = Record<string, unknown>> {
  /** STABLE event identifier. Use it for idempotency. */
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

/** `data` of `biometrics.session.completed` and `.review_required`. */
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
