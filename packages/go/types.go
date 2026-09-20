package biometrics

// Wire contract of Catalisa Biometrics, mirroring `src/biometrics/types` of the
// building block. Vocabularies (status, reason, gesture…) are plain strings on
// purpose: the server adds values over time, and an unknown one must not break
// an integration that is already running. The constants below name the ones
// that exist today.

type (
	Flow           = string
	SessionStatus  = string
	ProviderType   = string
	Assurance      = string
	CaptureMode    = string
	CaptureChannel = string
	Gesture        = string
	CheckKind      = string
	CheckStatus    = string
	Reason         = string
	// Environment is the world a key — and therefore a session — belongs to.
	Environment = string
)

const (
	FlowOnboarding     Flow = "ONBOARDING"
	FlowAuthentication Flow = "AUTHENTICATION"
	FlowEnrollment     Flow = "ENROLLMENT"
	FlowLivenessOnly   Flow = "LIVENESS_ONLY"
	FlowDedup          Flow = "DEDUP"
)

const (
	StatusSessionOpen  SessionStatus = "SESSION_OPEN"
	StatusProcessing   SessionStatus = "PROCESSING"
	StatusApproved     SessionStatus = "APPROVED"
	StatusRejected     SessionStatus = "REJECTED"
	StatusInconclusive SessionStatus = "INCONCLUSIVE"
	StatusRetryAllowed SessionStatus = "RETRY_ALLOWED"
	StatusExpired      SessionStatus = "EXPIRED"
	StatusCancelled    SessionStatus = "CANCELLED"
	StatusError        SessionStatus = "ERROR"
)

// EnvironmentTest is the sandbox: simulated engine, result driven by the CPF
// ending, no allowance spent and nothing billed.
const (
	EnvironmentTest Environment = "test"
	EnvironmentLive Environment = "live"
)

// terminalStatuses are the ones a session never leaves.
var terminalStatuses = map[SessionStatus]bool{
	StatusApproved: true, StatusRejected: true, StatusInconclusive: true,
	StatusExpired: true, StatusCancelled: true,
}

// IsTerminal says whether the session has settled — nothing will change after this.
func IsTerminal(status SessionStatus) bool { return terminalStatuses[status] }

type CheckEngine struct {
	Name    string `json:"name"`
	Model   string `json:"model"`
	Version string `json:"version"`
}

type Check struct {
	Kind      CheckKind      `json:"kind"`
	Status    CheckStatus    `json:"status"`
	Score     float64        `json:"score"`
	Threshold float64        `json:"threshold"`
	Reasons   []Reason       `json:"reasons"`
	Engine    CheckEngine    `json:"engine"`
	Details   map[string]any `json:"details,omitempty"`
}

type Decision struct {
	Outcome        SessionStatus `json:"outcome"`
	Reasons        []Reason      `json:"reasons"`
	PolicyID       string        `json:"policyId"`
	ReviewRequired bool          `json:"reviewRequired"`
	PolicyOverride *string       `json:"policyOverride"`
}

type EvidenceArtifact struct {
	Kind        string  `json:"kind"`
	FileID      *string `json:"fileId"`
	Hash        string  `json:"hash"`
	ContentType string  `json:"contentType"`
}

// EvidenceSignature covers `${sessionId}|${attempt}|${bundleHash}|${signedAt}`,
// signed with Ed25519 and encoded in base64. VerifyEvidence checks it offline.
type EvidenceSignature struct {
	Alg      string `json:"alg"`
	KeyID    string `json:"keyId"`
	SignedAt string `json:"signedAt"`
	Value    string `json:"value"`
}

type EvidenceClient struct {
	IPHash               *string `json:"ipHash"`
	UserAgent            *string `json:"userAgent"`
	CaptureTelemetryHash *string `json:"captureTelemetryHash"`
}

type Evidence struct {
	BundleHash         string             `json:"bundleHash"`
	Artifacts          []EvidenceArtifact `json:"artifacts"`
	Client             EvidenceClient     `json:"client"`
	PolicySnapshotHash string             `json:"policySnapshotHash"`
	RetainedUntil      *string            `json:"retainedUntil"`
	Signature          *EvidenceSignature `json:"signature,omitempty"`
}

// EvidenceDownload is a short-lived link to one artifact.
type EvidenceDownload struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
}

// EvidenceWithURLs is what `GET /sessions/{id}/evidence` answers.
type EvidenceWithURLs struct {
	Evidence
	URLs map[string]*EvidenceDownload `json:"urls"`
}

type Challenge struct {
	Script       []Gesture `json:"script"`
	TimeoutMs    int       `json:"timeoutMs"`
	PerGestureMs int       `json:"perGestureMs"`
	SlotsMs      []int     `json:"slotsMs,omitempty"`
}

// Handoff is how the person gets to the capture. Open CaptureURL in a browser
// tab, an iframe or a WebView; CaptureToken is only for custom capture.
type Handoff struct {
	CaptureURL   string         `json:"captureUrl"`
	CaptureToken string         `json:"captureToken"`
	CaptureMode  CaptureMode    `json:"captureMode"`
	Challenge    *Challenge     `json:"challenge,omitempty"`
	Provider     map[string]any `json:"provider,omitempty"`
	ExpiresAt    string         `json:"expiresAt"`
}

type EvaluationConformance struct {
	ProfileID  string   `json:"profileId"`
	Label      string   `json:"label"`
	Standard   string   `json:"standard"`
	Conforms   bool     `json:"conforms"`
	Certified  bool     `json:"certified"`
	Violations []string `json:"violations"`
}

type SubjectRef struct {
	Type   string `json:"type"`
	HMAC   string `json:"hmac"`
	Masked string `json:"masked"`
}

type ReferenceDocument struct {
	Authenticity string         `json:"authenticity"`
	MRZ          map[string]any `json:"mrz"`
	QR           map[string]any `json:"qr"`
}

type Reference struct {
	Source            *string            `json:"source"`
	FileID            *string            `json:"fileId"`
	TemplateID        *string            `json:"templateId"`
	PortraitExtracted bool               `json:"portraitExtracted"`
	Document          *ReferenceDocument `json:"document"`
}

type CaptureInfo struct {
	Channel   *CaptureChannel `json:"channel"`
	EmbedHost *string         `json:"embedHost"`
}

type Cost struct {
	Amount    string `json:"amount"`
	Currency  string `json:"currency"`
	Estimated bool   `json:"estimated"`
}

// Session is the envelope every session call answers with. The decision lives in
// Decision and Checks; the capture page never reveals it to the person in front
// of the camera, so it cannot be used as a fraud oracle.
type Session struct {
	SessionID   string                 `json:"sessionId"`
	Modality    string                 `json:"modality"`
	Flow        Flow                   `json:"flow"`
	Provider    ProviderType           `json:"provider"`
	Assurance   Assurance              `json:"assurance"`
	Evaluation  *EvaluationConformance `json:"evaluation"`
	Status      SessionStatus          `json:"status"`
	Attempt     int                    `json:"attempt"`
	MaxAttempts int                    `json:"maxAttempts"`
	SubjectRef  *SubjectRef            `json:"subjectRef"`
	CustomerID  *string                `json:"customerId"`
	Purpose     string                 `json:"purpose"`
	Reference   *Reference             `json:"reference"`
	Capture     *CaptureInfo           `json:"capture"`
	Metadata    map[string]string      `json:"metadata"`
	Enrollment  *struct {
		TemplateID string `json:"templateId"`
	} `json:"enrollment"`
	Decision *Decision `json:"decision"`
	Checks   []Check   `json:"checks"`
	// Handoff comes with a freshly created session and with every new attempt.
	Handoff     *Handoff  `json:"handoff,omitempty"`
	Evidence    *Evidence `json:"evidence"`
	Cost        *Cost     `json:"cost"`
	CreatedAt   string    `json:"createdAt"`
	CapturedAt  *string   `json:"capturedAt"`
	EvaluatedAt *string   `json:"evaluatedAt"`
	ExpiresAt   string    `json:"expiresAt"`
	ElapsedMs   *int      `json:"elapsedMs"`
	// SubaccountID is the tenant's customer that owns the session; nil means the
	// session belongs to the organization itself.
	SubaccountID *string `json:"subaccountId,omitempty"`
	// Environment is "test" (sandbox) or "live". Servers older than the sandbox
	// omit it — treat the empty string as "live".
	Environment Environment `json:"environment,omitempty"`
}

// IsSandbox says whether this session was a rehearsal: simulated engine, no
// allowance spent, never billed.
func (s *Session) IsSandbox() bool { return s.Environment == EnvironmentTest }

// SubjectInput identifies the person. Only the HMAC and a mask are stored; the
// CPF itself never is. In the sandbox the ending decides the outcome.
type SubjectInput struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ReferenceInput is what the face is compared against, per flow.
type ReferenceInput struct {
	Source     string `json:"source"`
	FileID     string `json:"fileId,omitempty"`
	TemplateID string `json:"templateId,omitempty"`
}

type Appearance struct {
	Colors    map[string]string `json:"colors,omitempty"`
	Radius    *int              `json:"radius,omitempty"`
	LogoURL   string            `json:"logoUrl,omitempty"`
	BrandName string            `json:"brandName,omitempty"`
	Locale    string            `json:"locale,omitempty"`
}

// CreateSessionInput is the body of `POST /sessions`. Flow and Purpose are
// required; Purpose is what you will show an auditor asking why this person's
// face was processed.
type CreateSessionInput struct {
	Flow             Flow            `json:"flow"`
	Purpose          string          `json:"purpose"`
	LegalBasis       string          `json:"legalBasis,omitempty"`
	SubjectRef       *SubjectInput   `json:"subjectRef,omitempty"`
	CustomerID       string          `json:"customerId,omitempty"`
	Reference        *ReferenceInput `json:"reference,omitempty"`
	ProviderConfigID string          `json:"providerConfigId,omitempty"`
	Appearance       *Appearance     `json:"appearance,omitempty"`
	// ChallengeScript is for testing and calibration; in production the server
	// draws the gestures.
	ChallengeScript []Gesture `json:"challengeScript,omitempty"`
	// Metadata takes up to 10 free-form labels. Never put a CPF here.
	Metadata map[string]string `json:"metadata,omitempty"`
	// EnrollOnApprove stores the face template when the session is approved.
	// ONBOARDING and ENROLLMENT only.
	EnrollOnApprove bool `json:"enrollOnApprove,omitempty"`
	// IdempotencyKey is forwarded as a header for forward compatibility; the
	// server does not deduplicate by it yet.
	IdempotencyKey string `json:"-"`
}

// ListSessionsInput filters `GET /sessions`. Prefer CustomerID over SubjectCPF:
// the CPF travels in the query string.
type ListSessionsInput struct {
	Page         int
	PageSize     int
	Status       SessionStatus
	Flow         Flow
	CustomerID   string
	SubjectCPF   string
	From         string
	To           string
	SubaccountID string
	// Environment filters by world when the caller is not sealed into one (an
	// organization key or a JWT). A subaccount key always sees only its own.
	Environment Environment
}

type SessionList struct {
	Data []Session `json:"data"`
	Meta struct {
		Total int `json:"total"`
		Page  struct {
			Number int `json:"number"`
			Size   int `json:"size"`
		} `json:"page"`
	} `json:"meta"`
}

// EvidenceKey is one published signing key. Retired keys stay published, so
// evidence signed in the past still verifies.
type EvidenceKey struct {
	KeyID        string  `json:"keyId"`
	PublicKeyPEM string  `json:"publicKeyPem"`
	CreatedAt    string  `json:"createdAt"`
	RetiredAt    *string `json:"retiredAt"`
}

// WebhookEvent is the body of every delivery. ID is stable: use it for idempotency.
type WebhookEvent struct {
	ID   string         `json:"id"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
	Meta struct {
		Timestamp      string `json:"timestamp"`
		CorrelationID  string `json:"correlationId,omitempty"`
		OrganizationID string `json:"organizationId,omitempty"`
	} `json:"metadata"`
}

const (
	EventSessionCreated        = "biometrics.session.created"
	EventSessionCompleted      = "biometrics.session.completed"
	EventSessionReviewRequired = "biometrics.session.review_required"
	EventSessionExpired        = "biometrics.session.expired"
)
