using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Catalisa.Biometrics;

/// <summary>Which check refused a delivery.</summary>
public enum WebhookFailure
{
    MissingHeaders,
    TimestampInvalid,
    TimestampOutOfTolerance,
    UnknownKeyId,
    UnsupportedSignatureVersion,
    InvalidSignature,
}

/// <summary>A delivery that failed verification. Answer 400 and do not process the body.</summary>
public sealed class WebhookVerificationException : Exception
{
    public WebhookFailure Failure { get; }

    public WebhookVerificationException(WebhookFailure failure, string message) : base(message)
    {
        Failure = failure;
    }
}

/// <summary>
/// Verifies Catalisa Webhooks Engine deliveries:
///
/// <code>
/// message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
/// signature = RSA-SHA256 (PKCS#1 v1.5), base64, in x-webhook-signature as "v1=&lt;base64&gt;"
/// key       = the subscription's PUBLIC key, chosen by x-webhook-key-id
/// </code>
///
/// The signature is asymmetric: there is no shared secret to leak. The engine
/// does not refuse old deliveries — the receiver enforces the tolerance, or a
/// captured delivery could be replayed forever.
/// </summary>
public sealed class WebhookVerifier
{
    private readonly IReadOnlyDictionary<string, string> _publicKeys;
    private readonly TimeSpan _tolerance;
    private readonly Func<DateTimeOffset> _now;

    /// <param name="publicKeys">keyId to PEM. Keep a retired key here while deliveries signed with it may still arrive.</param>
    /// <param name="tolerance">Default five minutes. <see cref="TimeSpan.Zero"/> disables the check (not recommended).</param>
    /// <param name="now">Reference clock, for tests.</param>
    public WebhookVerifier(
        IReadOnlyDictionary<string, string> publicKeys,
        TimeSpan? tolerance = null,
        Func<DateTimeOffset>? now = null)
    {
        _publicKeys = publicKeys;
        _tolerance = tolerance ?? TimeSpan.FromMinutes(5);
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Verifies a delivery and returns the parsed event.
    ///
    /// Pass the RAW body — the bytes as they arrived. Decoding and re-encoding the
    /// JSON changes them, and the signature will not match.
    /// </summary>
    public WebhookEvent Verify(Func<string, string?> header, string rawBody)
    {
        var id = header("x-webhook-id");
        var timestamp = header("x-webhook-timestamp");
        var keyId = header("x-webhook-key-id");
        var signature = header("x-webhook-signature");

        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(keyId) || string.IsNullOrEmpty(signature))
        {
            throw Fail(WebhookFailure.MissingHeaders, "missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature");
        }
        if (!DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var sentAt))
        {
            throw Fail(WebhookFailure.TimestampInvalid, "x-webhook-timestamp is not an ISO 8601 date");
        }
        if (_tolerance > TimeSpan.Zero)
        {
            var drift = _now() - sentAt;
            if (drift > _tolerance || drift < -_tolerance)
            {
                throw Fail(WebhookFailure.TimestampOutOfTolerance, "delivery is outside the time tolerance (possible replay)");
            }
        }
        if (!signature!.StartsWith("v1=", StringComparison.Ordinal))
        {
            throw Fail(WebhookFailure.UnsupportedSignatureVersion, "unsupported signature version (expected v1=)");
        }
        if (!_publicKeys.TryGetValue(keyId!, out var pem))
        {
            throw Fail(WebhookFailure.UnknownKeyId, "no public key for this x-webhook-key-id");
        }

        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(signature.Substring(3));
        }
        catch (FormatException)
        {
            throw Fail(WebhookFailure.InvalidSignature, "invalid signature");
        }

        var message = Encoding.UTF8.GetBytes($"{id}\n{timestamp}\n{rawBody}");
        bool valid;
        try
        {
            valid = Rsa.VerifySha256(pem, message, raw);
        }
        catch (Exception)
        {
            throw Fail(WebhookFailure.UnknownKeyId, "the public key for this keyId is not readable");
        }
        if (!valid)
        {
            throw Fail(WebhookFailure.InvalidSignature, "invalid signature");
        }

        try
        {
            return JsonSerializer.Deserialize<WebhookEvent>(rawBody)!;
        }
        catch (JsonException e)
        {
            throw Fail(WebhookFailure.InvalidSignature, "the signed body is not valid JSON: " + e.Message);
        }
    }

    private static WebhookVerificationException Fail(WebhookFailure failure, string message)
        => new(failure, message);
}

/// <summary>The outcome of checking an evidence signature offline.</summary>
public sealed record EvidenceVerification(bool Valid, string KeyId, bool UnknownKey, string? RetiredAt);

/// <summary>
/// OFFLINE verification of the signed evidence, without calling Catalisa:
///
/// <code>
/// message   = "{sessionId}|{attempt}|{bundleHash}|{signedAt}"
/// signature = Ed25519 (RFC 8032), base64
/// key       = GET /evidence-keys, by the signature's keyId
/// </code>
///
/// This is what lets a third party — an auditor, a court — confirm years later
/// that the bundle is the one Catalisa signed.
/// </summary>
public static class Evidence
{
    /// <summary>The exact string that was signed.</summary>
    public static string Message(string sessionId, int attempt, string bundleHash, string signedAt)
        => $"{sessionId}|{attempt}|{bundleHash}|{signedAt}";

    public static EvidenceVerification Verify(
        string sessionId,
        int attempt,
        string bundleHash,
        EvidenceSignature signature,
        IEnumerable<EvidenceKey> keys)
    {
        var key = keys.FirstOrDefault(k => k.KeyId == signature.KeyId);
        if (key is null)
        {
            return new EvidenceVerification(false, signature.KeyId, true, null);
        }
        if (signature.Alg != "Ed25519")
        {
            return new EvidenceVerification(false, signature.KeyId, false, key.RetiredAt);
        }

        byte[] raw;
        byte[] publicKey;
        try
        {
            raw = Convert.FromBase64String(signature.Value);
            publicKey = RawKeyFromPem(key.PublicKeyPem);
        }
        catch (FormatException)
        {
            return new EvidenceVerification(false, signature.KeyId, false, key.RetiredAt);
        }

        var message = Encoding.UTF8.GetBytes(Message(sessionId, attempt, bundleHash, signature.SignedAt));
        var valid = Ed25519.Verify(publicKey, message, raw);

        return new EvidenceVerification(valid, signature.KeyId, false, key.RetiredAt);
    }

    /// <summary>
    /// The 32 raw bytes of an Ed25519 key inside a PEM. The DER wrapper
    /// (SubjectPublicKeyInfo) is a fixed 12-byte header followed by the key, which
    /// is why taking the tail is enough — and why a key of another kind, being a
    /// different length, is refused here.
    /// </summary>
    private static byte[] RawKeyFromPem(string pem)
    {
        var body = pem
            .Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("\r", "")
            .Replace("\n", "")
            .Trim();
        var der = Convert.FromBase64String(body);
        if (der.Length != 44)
        {
            throw new FormatException("not an Ed25519 public key");
        }

        return der.Skip(12).ToArray();
    }
}
