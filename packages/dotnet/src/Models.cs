using System.Text.Json;
using System.Text.Json.Serialization;

namespace Catalisa.Biometrics;

// Wire contract of Catalisa Biometrics. The vocabularies (status, reason,
// gesture…) stay strings on purpose: the server adds values over time, and one
// you do not know yet must not break an integration that already runs. The
// constants below name the ones that exist today.

/// <summary>Sandbox or production. A key belongs to one; a session keeps the one it was born in.</summary>
public static class Environments
{
    /// <summary>Simulated engine, result driven by the CPF ending, no allowance spent, never billed.</summary>
    public const string Test = "test";
    public const string Live = "live";
}

public static class Flows
{
    public const string Onboarding = "ONBOARDING";
    public const string Authentication = "AUTHENTICATION";
    public const string Enrollment = "ENROLLMENT";
    public const string LivenessOnly = "LIVENESS_ONLY";
    public const string Dedup = "DEDUP";
}

public static class SessionStatuses
{
    public const string SessionOpen = "SESSION_OPEN";
    public const string Processing = "PROCESSING";
    public const string Approved = "APPROVED";
    public const string Rejected = "REJECTED";
    public const string Inconclusive = "INCONCLUSIVE";
    public const string RetryAllowed = "RETRY_ALLOWED";
    public const string Expired = "EXPIRED";
    public const string Cancelled = "CANCELLED";
    public const string Error = "ERROR";

    private static readonly HashSet<string> Terminal = new()
    {
        Approved, Rejected, Inconclusive, Expired, Cancelled,
    };

    /// <summary>The session has settled: nothing will change after this.</summary>
    public static bool IsTerminal(string? status) => status is not null && Terminal.Contains(status);
}

public sealed class CheckEngine
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("model")] public string Model { get; init; } = "";
    [JsonPropertyName("version")] public string Version { get; init; } = "";
}

/// <summary>One verification, with its number, the threshold it had to clear and the engine that ran it.</summary>
public sealed class Check
{
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("score")] public double Score { get; init; }
    [JsonPropertyName("threshold")] public double Threshold { get; init; }
    [JsonPropertyName("reasons")] public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    [JsonPropertyName("engine")] public CheckEngine? Engine { get; init; }
}

public sealed class Decision
{
    [JsonPropertyName("outcome")] public string Outcome { get; init; } = "";
    [JsonPropertyName("reasons")] public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    [JsonPropertyName("policyId")] public string PolicyId { get; init; } = "";
    [JsonPropertyName("reviewRequired")] public bool ReviewRequired { get; init; }
    [JsonPropertyName("policyOverride")] public string? PolicyOverride { get; init; }
}

public sealed class EvidenceArtifact
{
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
    [JsonPropertyName("fileId")] public string? FileId { get; init; }
    [JsonPropertyName("hash")] public string Hash { get; init; } = "";
    [JsonPropertyName("contentType")] public string ContentType { get; init; } = "";
}

/// <summary>
/// Covers <c>{sessionId}|{attempt}|{bundleHash}|{signedAt}</c>, signed with
/// Ed25519 and encoded in base64. <see cref="Evidence.Verify"/> checks it offline.
/// </summary>
public sealed class EvidenceSignature
{
    [JsonPropertyName("alg")] public string Alg { get; init; } = "";
    [JsonPropertyName("keyId")] public string KeyId { get; init; } = "";
    [JsonPropertyName("signedAt")] public string SignedAt { get; init; } = "";
    [JsonPropertyName("value")] public string Value { get; init; } = "";
}

public sealed class EvidenceBundle
{
    [JsonPropertyName("bundleHash")] public string BundleHash { get; init; } = "";
    [JsonPropertyName("artifacts")] public IReadOnlyList<EvidenceArtifact> Artifacts { get; init; } = Array.Empty<EvidenceArtifact>();
    [JsonPropertyName("policySnapshotHash")] public string PolicySnapshotHash { get; init; } = "";
    [JsonPropertyName("retainedUntil")] public string? RetainedUntil { get; init; }
    [JsonPropertyName("signature")] public EvidenceSignature? Signature { get; init; }
    [JsonPropertyName("urls")] public IReadOnlyDictionary<string, EvidenceDownload?>? Urls { get; init; }
}

public sealed class EvidenceDownload
{
    [JsonPropertyName("url")] public string Url { get; init; } = "";
    [JsonPropertyName("expiresAt")] public string ExpiresAt { get; init; } = "";
}

/// <summary>One published signing key. Retired keys stay published, so old evidence still verifies.</summary>
public sealed class EvidenceKey
{
    [JsonPropertyName("keyId")] public string KeyId { get; init; } = "";
    [JsonPropertyName("publicKeyPem")] public string PublicKeyPem { get; init; } = "";
    [JsonPropertyName("createdAt")] public string CreatedAt { get; init; } = "";
    [JsonPropertyName("retiredAt")] public string? RetiredAt { get; init; }
}

public sealed class Challenge
{
    [JsonPropertyName("script")] public IReadOnlyList<string> Script { get; init; } = Array.Empty<string>();
    [JsonPropertyName("timeoutMs")] public int TimeoutMs { get; init; }
    [JsonPropertyName("perGestureMs")] public int PerGestureMs { get; init; }
}

/// <summary>How the person gets to the capture. Open <see cref="CaptureUrl"/>; the token is for custom capture.</summary>
public sealed class Handoff
{
    [JsonPropertyName("captureUrl")] public string CaptureUrl { get; init; } = "";
    [JsonPropertyName("captureToken")] public string CaptureToken { get; init; } = "";
    [JsonPropertyName("captureMode")] public string CaptureMode { get; init; } = "";
    [JsonPropertyName("challenge")] public Challenge? Challenge { get; init; }
    [JsonPropertyName("expiresAt")] public string ExpiresAt { get; init; } = "";
}

public sealed class SubjectRef
{
    [JsonPropertyName("type")] public string Type { get; init; } = "";
    [JsonPropertyName("hmac")] public string Hmac { get; init; } = "";
    [JsonPropertyName("masked")] public string Masked { get; init; } = "";
}

public sealed class Cost
{
    [JsonPropertyName("amount")] public string Amount { get; init; } = "";
    [JsonPropertyName("currency")] public string Currency { get; init; } = "";
    [JsonPropertyName("estimated")] public bool Estimated { get; init; }
}

/// <summary>
/// The envelope every session call answers with. The decision lives in
/// <see cref="Decision"/> and <see cref="Checks"/>; the capture page never
/// reveals it to the person in front of the camera, so it cannot be used as a
/// fraud oracle.
/// </summary>
public sealed class Session
{
    [JsonPropertyName("sessionId")] public string SessionId { get; init; } = "";
    [JsonPropertyName("subaccountId")] public string? SubaccountId { get; init; }

    /// <summary>"test" (sandbox) or "live". Servers older than the sandbox omit it — treat empty as live.</summary>
    [JsonPropertyName("environment")] public string? Environment { get; init; }

    [JsonPropertyName("modality")] public string Modality { get; init; } = "";
    [JsonPropertyName("flow")] public string Flow { get; init; } = "";
    [JsonPropertyName("provider")] public string Provider { get; init; } = "";
    [JsonPropertyName("assurance")] public string Assurance { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("attempt")] public int Attempt { get; init; }
    [JsonPropertyName("maxAttempts")] public int MaxAttempts { get; init; }
    [JsonPropertyName("subjectRef")] public SubjectRef? SubjectRef { get; init; }
    [JsonPropertyName("customerId")] public string? CustomerId { get; init; }
    [JsonPropertyName("purpose")] public string Purpose { get; init; } = "";
    [JsonPropertyName("metadata")] public IReadOnlyDictionary<string, string>? Metadata { get; init; }
    [JsonPropertyName("decision")] public Decision? Decision { get; init; }
    [JsonPropertyName("checks")] public IReadOnlyList<Check> Checks { get; init; } = Array.Empty<Check>();

    /// <summary>Comes with a freshly created session and with every new attempt.</summary>
    [JsonPropertyName("handoff")] public Handoff? Handoff { get; init; }

    [JsonPropertyName("evidence")] public EvidenceBundle? Evidence { get; init; }
    [JsonPropertyName("cost")] public Cost? Cost { get; init; }
    [JsonPropertyName("createdAt")] public string CreatedAt { get; init; } = "";
    [JsonPropertyName("capturedAt")] public string? CapturedAt { get; init; }
    [JsonPropertyName("evaluatedAt")] public string? EvaluatedAt { get; init; }
    [JsonPropertyName("expiresAt")] public string ExpiresAt { get; init; } = "";
    [JsonPropertyName("elapsedMs")] public int? ElapsedMs { get; init; }

    /// <summary>A rehearsal: simulated engine, no allowance spent, never billed.</summary>
    [JsonIgnore] public bool IsSandbox => Environment == Environments.Test;

    /// <summary>The session has settled: nothing will change after this.</summary>
    [JsonIgnore] public bool IsTerminal => SessionStatuses.IsTerminal(Status);
}

public sealed class SessionPage
{
    [JsonPropertyName("data")] public IReadOnlyList<Session> Data { get; init; } = Array.Empty<Session>();
    [JsonPropertyName("meta")] public JsonElement Meta { get; init; }
}

/// <summary>
/// What the capture endpoint answers. Deliberately poorer than the envelope:
/// score, checks and the full decision never come back here.
/// </summary>
public sealed class CaptureResult
{
    [JsonPropertyName("sessionId")] public string SessionId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("attempt")] public int Attempt { get; init; }
    [JsonPropertyName("maxAttempts")] public int MaxAttempts { get; init; }

    /// <summary>Only on RETRY_ALLOWED, and only quality/gesture reasons.</summary>
    [JsonPropertyName("reasons")] public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    /// <summary>A fresh token and challenge, when another attempt is allowed.</summary>
    [JsonPropertyName("handoff")] public Handoff? Handoff { get; init; }
}

/// <summary>Body of every webhook delivery. <see cref="Id"/> is stable: use it for idempotency.</summary>
public sealed class WebhookEvent
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("type")] public string Type { get; init; } = "";
    [JsonPropertyName("data")] public JsonElement Data { get; init; }
    [JsonPropertyName("metadata")] public JsonElement Metadata { get; init; }
}

public static class WebhookEvents
{
    public const string SessionCreated = "biometrics.session.created";
    public const string SessionCompleted = "biometrics.session.completed";
    public const string SessionReviewRequired = "biometrics.session.review_required";
    public const string SessionExpired = "biometrics.session.expired";
}
