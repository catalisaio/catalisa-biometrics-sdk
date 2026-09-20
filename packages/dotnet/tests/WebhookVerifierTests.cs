using System.Text.Json;
using Xunit;

namespace Catalisa.Biometrics.Tests;

/// <summary>
/// The vectors are shared by every SDK in this repository and were produced by the
/// building block's own signing code, so "it passes here" means the same thing in
/// each language.
/// </summary>
public class WebhookVerifierTests
{
    private static JsonElement Vectors()
    {
        var raw = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json"));
        return JsonDocument.Parse(raw).RootElement.Clone();
    }

    private static (WebhookVerifier Verifier, Func<string, string?> Header, string Body) Delivery(
        DateTimeOffset? now = null,
        TimeSpan? tolerance = null,
        string? overrideHeader = null,
        string? overrideValue = null)
    {
        var webhook = Vectors().GetProperty("webhook");
        var keys = webhook.GetProperty("keys").EnumerateObject()
            .ToDictionary(p => p.Name, p => p.Value.GetString()!);
        var headers = webhook.GetProperty("headers").EnumerateObject()
            .ToDictionary(p => p.Name, p => p.Value.GetString());
        if (overrideHeader is not null) headers[overrideHeader] = overrideValue;

        var at = now ?? DateTimeOffset.Parse(webhook.GetProperty("now").GetString()!);
        var verifier = new WebhookVerifier(keys, tolerance, () => at);

        return (verifier, name => headers.TryGetValue(name, out var value) ? value : null, webhook.GetProperty("body").GetString()!);
    }

    [Fact]
    public void AcceptsAGenuineDelivery()
    {
        var (verifier, header, body) = Delivery();

        var evt = verifier.Verify(header, body);

        Assert.False(string.IsNullOrEmpty(evt.Id));
        Assert.Equal(WebhookEvents.SessionCompleted, evt.Type);
    }

    [Fact]
    public void RejectsATamperedBody()
    {
        var webhook = Vectors().GetProperty("webhook");
        var (verifier, header, _) = Delivery();

        var error = Assert.Throws<WebhookVerificationException>(() =>
            verifier.Verify(header, webhook.GetProperty("tamperedBody").GetString()!));

        Assert.Equal(WebhookFailure.InvalidSignature, error.Failure);
    }

    [Fact]
    public void RejectsAnOldDelivery()
    {
        // The engine does not refuse old deliveries — the receiver does, or a
        // captured delivery could be replayed forever.
        var webhook = Vectors().GetProperty("webhook");
        var sentAt = DateTimeOffset.Parse(webhook.GetProperty("headers").GetProperty("x-webhook-timestamp").GetString()!);
        var (verifier, header, body) = Delivery(now: sentAt.AddMinutes(10));

        var error = Assert.Throws<WebhookVerificationException>(() => verifier.Verify(header, body));
        Assert.Equal(WebhookFailure.TimestampOutOfTolerance, error.Failure);

        var (wide, wideHeader, wideBody) = Delivery(now: sentAt.AddMinutes(10), tolerance: TimeSpan.FromHours(1));
        Assert.False(string.IsNullOrEmpty(wide.Verify(wideHeader, wideBody).Id));
    }

    [Fact]
    public void RejectsMissingHeadersUnknownKeyAndAnotherVersion()
    {
        var (verifier, _, body) = Delivery();
        var bare = Assert.Throws<WebhookVerificationException>(() => verifier.Verify(_ => null, body));
        Assert.Equal(WebhookFailure.MissingHeaders, bare.Failure);

        var (unknownKey, unknownHeader, unknownBody) = Delivery(overrideHeader: "x-webhook-key-id", overrideValue: "whk_not_mine");
        var unknown = Assert.Throws<WebhookVerificationException>(() => unknownKey.Verify(unknownHeader, unknownBody));
        Assert.Equal(WebhookFailure.UnknownKeyId, unknown.Failure);

        var (oldVersion, oldHeader, oldBody) = Delivery(overrideHeader: "x-webhook-signature", overrideValue: "v2=abc");
        var version = Assert.Throws<WebhookVerificationException>(() => oldVersion.Verify(oldHeader, oldBody));
        Assert.Equal(WebhookFailure.UnsupportedSignatureVersion, version.Failure);
    }

    [Fact]
    public void VerifiesEvidenceOffline()
    {
        var evidence = Vectors().GetProperty("evidence");
        var keys = evidence.GetProperty("evidenceKeysResponse").GetProperty("data")
            .EnumerateArray()
            .Select(k => new EvidenceKey
            {
                KeyId = k.GetProperty("keyId").GetString()!,
                PublicKeyPem = k.GetProperty("publicKeyPem").GetString()!,
                RetiredAt = k.TryGetProperty("retiredAt", out var retired) && retired.ValueKind == JsonValueKind.String ? retired.GetString() : null,
            })
            .ToList();
        var raw = evidence.GetProperty("evidence").GetProperty("signature");
        var signature = new EvidenceSignature
        {
            Alg = raw.GetProperty("alg").GetString()!,
            KeyId = raw.GetProperty("keyId").GetString()!,
            SignedAt = raw.GetProperty("signedAt").GetString()!,
            Value = raw.GetProperty("value").GetString()!,
        };
        var sessionId = evidence.GetProperty("sessionId").GetString()!;
        var attempt = evidence.GetProperty("attempt").GetInt32();
        var bundleHash = evidence.GetProperty("evidence").GetProperty("bundleHash").GetString()!;

        var ok = Evidence.Verify(sessionId, attempt, bundleHash, signature, keys);
        Assert.True(ok.Valid);
        Assert.False(ok.UnknownKey);

        // Any change to what was signed breaks it — that is the whole point.
        Assert.False(Evidence.Verify(sessionId, attempt + 1, bundleHash, signature, keys).Valid);
        Assert.False(Evidence.Verify(sessionId, attempt, "0000", signature, keys).Valid);

        var unknown = Evidence.Verify(sessionId, attempt, bundleHash, new EvidenceSignature { Alg = signature.Alg, KeyId = "ev-unknown", SignedAt = signature.SignedAt, Value = signature.Value }, keys);
        Assert.True(unknown.UnknownKey);
        Assert.False(unknown.Valid);
    }
}
