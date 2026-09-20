using System.Text.Json;

namespace Catalisa.Biometrics;

/// <summary>
/// Every failed call throws this. The API answers
/// <c>{"error":"&lt;code&gt;","message":"...","details":{...}}</c>, so
/// <see cref="ErrorCode"/> is the API's own word for what happened — branch on
/// it, never on the message.
/// </summary>
public sealed class BiometricsException : Exception
{
    /// <summary>HTTP status, or 0 when the request never reached the API.</summary>
    public int Status { get; }

    /// <summary>
    /// API error code (VALIDATION, NOT_FOUND, QUOTA_EXCEEDED…), or TIMEOUT /
    /// CONNECTION when the request did not complete.
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>Whatever the API attached: the offending fields, the quota numbers.</summary>
    public IReadOnlyDictionary<string, JsonElement> Details { get; }

    /// <summary><c>x-request-id</c>, when the API sends one — quote it in a support ticket.</summary>
    public string? RequestId { get; }

    /// <summary><c>Retry-After</c> in seconds, on a 429.</summary>
    public int? RetryAfter { get; }

    public BiometricsException(
        int status,
        string errorCode,
        string message,
        IReadOnlyDictionary<string, JsonElement>? details = null,
        string? requestId = null,
        int? retryAfter = null)
        : base(message)
    {
        Status = status;
        ErrorCode = errorCode;
        Details = details ?? new Dictionary<string, JsonElement>();
        RequestId = requestId;
        RetryAfter = retryAfter;
    }

    /// <summary>The customer's monthly allowance is gone. A test key never gets here.</summary>
    public bool IsQuotaExceeded => ErrorCode == "QUOTA_EXCEEDED";

    /// <summary>The subaccount is suspended: nothing opens until it is reactivated.</summary>
    public bool IsSubaccountSuspended => ErrorCode == "SUBACCOUNT_SUSPENDED";

    /// <summary>Worth trying again by itself: rate limit, server fault or network.</summary>
    public bool IsTransient => Status == 429 || Status >= 500 || Status == 0;

    internal static BiometricsException FromResponse(int status, string? body, Func<string, string?> header)
    {
        var code = CodeForStatus(status);
        var message = "";
        Dictionary<string, JsonElement>? details = null;

        if (!string.IsNullOrWhiteSpace(body))
        {
            try
            {
                using var document = JsonDocument.Parse(body!);
                var root = document.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                {
                    if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String)
                    {
                        code = error.GetString() ?? code;
                    }
                    if (root.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String)
                    {
                        message = text.GetString() ?? "";
                    }
                    if (root.TryGetProperty("details", out var raw) && raw.ValueKind == JsonValueKind.Object)
                    {
                        details = new Dictionary<string, JsonElement>();
                        foreach (var property in raw.EnumerateObject())
                        {
                            details[property.Name] = property.Value.Clone();
                        }
                        // The machine-readable code lives inside details on the cases
                        // that carry numbers with them (quota, suspension).
                        if (details.TryGetValue("code", out var inner) && inner.ValueKind == JsonValueKind.String)
                        {
                            code = inner.GetString() ?? code;
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // A proxy in front of the API can answer HTML. The caller still needs
                // a code, and the status gives one.
            }
        }

        if (message.Length == 0)
        {
            message = MessageForStatus(status);
        }

        int? retryAfter = null;
        if (int.TryParse(header("Retry-After"), out var seconds))
        {
            retryAfter = seconds;
        }

        return new BiometricsException(status, code, message, details, header("x-request-id"), retryAfter);
    }

    private static string CodeForStatus(int status) => status switch
    {
        400 => "VALIDATION",
        401 => "UNAUTHORIZED",
        402 => "QUOTA_EXCEEDED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        409 => "CONFLICT",
        413 => "PAYLOAD_TOO_LARGE",
        415 => "VALIDATION",
        429 => "RATE_LIMITED",
        >= 500 => "INTERNAL",
        _ => "ERROR",
    };

    private static string MessageForStatus(int status) => status switch
    {
        401 => "API key missing, wrong or revoked",
        402 => "monthly allowance exhausted",
        403 => "this key may not do that",
        404 => "not found in this scope",
        429 => "too many requests",
        >= 500 => "the API failed",
        _ => $"request failed with status {status}",
    };
}
