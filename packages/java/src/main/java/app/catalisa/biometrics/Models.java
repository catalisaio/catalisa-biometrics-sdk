package app.catalisa.biometrics;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Wire contract of Catalisa Biometrics.
 *
 * <p>The vocabularies (status, reason, gesture…) stay strings on purpose: the
 * server adds values over time, and one you do not know yet must not break an
 * integration that already runs. The constants name the ones that exist today.
 */
public final class Models {

    private Models() {
    }

    /** Sandbox or production. A key belongs to one; a session keeps the one it was born in. */
    public static final class Environments {
        /** Simulated engine, result driven by the CPF ending, no allowance spent, never billed. */
        public static final String TEST = "test";
        public static final String LIVE = "live";

        private Environments() {
        }
    }

    public static final class Flows {
        public static final String ONBOARDING = "ONBOARDING";
        public static final String AUTHENTICATION = "AUTHENTICATION";
        public static final String ENROLLMENT = "ENROLLMENT";
        public static final String LIVENESS_ONLY = "LIVENESS_ONLY";
        public static final String DEDUP = "DEDUP";

        private Flows() {
        }
    }

    public static final class Statuses {
        public static final String SESSION_OPEN = "SESSION_OPEN";
        public static final String PROCESSING = "PROCESSING";
        public static final String APPROVED = "APPROVED";
        public static final String REJECTED = "REJECTED";
        public static final String INCONCLUSIVE = "INCONCLUSIVE";
        public static final String RETRY_ALLOWED = "RETRY_ALLOWED";
        public static final String EXPIRED = "EXPIRED";
        public static final String CANCELLED = "CANCELLED";
        public static final String ERROR = "ERROR";

        private static final List<String> TERMINAL =
                List.of(APPROVED, REJECTED, INCONCLUSIVE, EXPIRED, CANCELLED);

        /** The session has settled: nothing will change after this. */
        public static boolean isTerminal(String status) {
            return TERMINAL.contains(status);
        }

        private Statuses() {
        }
    }

    public record CheckEngine(String name, String model, String version) {
    }

    /** One verification, with its number, the threshold it had to clear and the engine that ran it. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Check(String kind, String status, double score, double threshold,
                        List<String> reasons, CheckEngine engine, Map<String, Object> details) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Decision(String outcome, List<String> reasons, String policyId,
                           boolean reviewRequired, String policyOverride) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EvidenceArtifact(String kind, String fileId, String hash, String contentType) {
    }

    /**
     * Covers {@code {sessionId}|{attempt}|{bundleHash}|{signedAt}}, signed with
     * Ed25519 and encoded in base64. {@link app.catalisa.biometrics.Evidence#verify} checks it offline.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EvidenceSignature(String alg, String keyId, String signedAt, String value) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EvidenceDownload(String url, String expiresAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Evidence(String bundleHash, List<EvidenceArtifact> artifacts,
                           String policySnapshotHash, String retainedUntil,
                           EvidenceSignature signature, Map<String, EvidenceDownload> urls) {
    }

    /** One published signing key. Retired keys stay published, so old evidence still verifies. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EvidenceKey(String keyId, String publicKeyPem, String createdAt, String retiredAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Challenge(List<String> script, int timeoutMs, int perGestureMs, List<Integer> slotsMs) {
    }

    /** How the person gets to the capture. Open {@code captureUrl}; the token is for custom capture. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Handoff(String captureUrl, String captureToken, String captureMode,
                          Challenge challenge, String expiresAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SubjectRef(String type, String hmac, String masked) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Cost(String amount, String currency, boolean estimated) {
    }

    /**
     * The envelope every session call answers with. The decision lives in
     * {@code decision} and {@code checks}; the capture page never reveals it to
     * the person in front of the camera, so it cannot be used as a fraud oracle.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Session(
            String sessionId,
            String subaccountId,
            /* "test" (sandbox) or "live"; servers older than the sandbox omit it. */
            String environment,
            String modality,
            String flow,
            String provider,
            String assurance,
            String status,
            int attempt,
            int maxAttempts,
            SubjectRef subjectRef,
            String customerId,
            String purpose,
            Map<String, String> metadata,
            Decision decision,
            List<Check> checks,
            /* Comes with a freshly created session and with every new attempt. */
            Handoff handoff,
            Evidence evidence,
            Cost cost,
            String createdAt,
            String capturedAt,
            String evaluatedAt,
            String expiresAt,
            Integer elapsedMs) {

        /** A rehearsal: simulated engine, no allowance spent, never billed. */
        public boolean isSandbox() {
            return Environments.TEST.equals(environment);
        }

        /** The session has settled: nothing will change after this. */
        public boolean isTerminal() {
            return Statuses.isTerminal(status);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SessionPage(List<Session> data, Map<String, Object> meta) {
    }

    /**
     * What the capture endpoint answers. Deliberately poorer than the envelope:
     * score, checks and the full decision never come back here.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CaptureResult(String sessionId, String status, int attempt, int maxAttempts,
                                List<String> reasons, Handoff handoff) {
    }

    /** Body of every webhook delivery. {@code id} is stable: use it for idempotency. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record WebhookEvent(String id, String type, Map<String, Object> data,
                               @JsonProperty("metadata") Map<String, Object> metadata) {
    }

    public static final class WebhookEvents {
        public static final String SESSION_CREATED = "biometrics.session.created";
        public static final String SESSION_COMPLETED = "biometrics.session.completed";
        public static final String SESSION_REVIEW_REQUIRED = "biometrics.session.review_required";
        public static final String SESSION_EXPIRED = "biometrics.session.expired";

        private WebhookEvents() {
        }
    }
}
