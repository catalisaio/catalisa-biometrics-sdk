using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Catalisa.Biometrics;

/// <summary>Options for <see cref="BiometricsClient"/>. Only the key is required.</summary>
public sealed class BiometricsOptions
{
    /// <summary>Key from the console. A test key runs the sandbox.</summary>
    public string ApiKey { get; init; } = "";

    /// <summary>An IAM JWT instead of an API key.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Defaults to the public API; point it elsewhere for a dedicated deployment.</summary>
    public string BaseUrl { get; init; } = BiometricsClient.DefaultBaseUrl;

    /// <summary>Act on behalf of a subaccount while holding an organization key.</summary>
    public string? SubaccountId { get; init; }

    /// <summary>Per attempt. Thirty seconds by default.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Retries for reads and for 429. Session creation is never retried on 5xx.</summary>
    public int MaxRetries { get; init; } = 2;

    /// <summary>Replaces the transport (tests, proxies, instrumentation).</summary>
    public HttpMessageHandler? Handler { get; init; }

    /// <summary>Replaces the wait between attempts, in tests.</summary>
    internal Func<TimeSpan, CancellationToken, Task>? Delay { get; init; }
}

/// <summary>
/// Catalisa Biometrics client.
///
/// The flow never trusts the browser:
/// <list type="number">
///   <item>your server creates a session and gets <c>Handoff.CaptureUrl</c>;</item>
///   <item>the person opens that URL (tab, iframe or WebView) and does the challenge;</item>
///   <item>the decision reaches your server through the webhook, or through <see cref="GetSessionAsync"/>.</item>
/// </list>
///
/// The capture page never shows the result to the person in front of the camera,
/// on purpose: it would be a fraud oracle. Never decide anything from front-end
/// events.
/// </summary>
public sealed class BiometricsClient : IDisposable
{
    /// <summary>The public API.</summary>
    public const string DefaultBaseUrl = "https://api.biometrics.catalisa.app/v1";

    /// <summary>Version of this SDK, sent in the User-Agent.</summary>
    public const string Version = "0.1.0";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly BiometricsOptions _options;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    /// <summary>Builds a client. Fails only when no credential is given.</summary>
    public BiometricsClient(BiometricsOptions options)
    {
        if (string.IsNullOrEmpty(options.ApiKey) && string.IsNullOrEmpty(options.AccessToken))
        {
            throw new ArgumentException("Catalisa Biometrics: an API key (or an access token) is required", nameof(options));
        }
        _options = options;
        _http = options.Handler is null ? new HttpClient() : new HttpClient(options.Handler);
        _http.Timeout = options.Timeout;
        _ownsHttpClient = true;
    }

    /// <summary>Shorthand for the common case: just the key.</summary>
    public BiometricsClient(string apiKey) : this(new BiometricsOptions { ApiKey = apiKey })
    {
    }

    /// <summary>
    /// Opens a session. The answer carries <c>Handoff.CaptureUrl</c>, where the
    /// person goes.
    ///
    /// Never retried on a 5xx or a network failure: the server does not
    /// deduplicate by Idempotency-Key yet, and a retry could open two sessions
    /// (and spend the allowance twice).
    /// </summary>
    public async Task<Session> CreateSessionAsync(
        CreateSessionInput input,
        string? idempotencyKey = null,
        CancellationToken cancellationToken = default)
    {
        var headers = idempotencyKey is null
            ? null
            : new Dictionary<string, string> { ["Idempotency-Key"] = idempotencyKey };

        var envelope = await SendAsync<Envelope<Session>>(
            HttpMethod.Post, "/sessions", query: null, body: input, headers: headers, idempotent: false,
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return envelope.Data!;
    }

    /// <summary>
    /// Reads a session. One from another subaccount — or from the other
    /// environment — answers NotFound, on purpose: existence is not confirmed.
    /// </summary>
    public async Task<Session> GetSessionAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var envelope = await SendAsync<Envelope<Session>>(
            HttpMethod.Get, $"/sessions/{Uri.EscapeDataString(sessionId)}", idempotent: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return envelope.Data!;
    }

    /// <summary>Lists sessions, newest first.</summary>
    public Task<SessionPage> ListSessionsAsync(ListSessionsInput? filter = null, CancellationToken cancellationToken = default)
    {
        var query = new Dictionary<string, string?>();
        if (filter is not null)
        {
            if (filter.Page is int page) query["page[number]"] = page.ToString();
            if (filter.PageSize is int size) query["page[size]"] = size.ToString();
            query["status"] = filter.Status;
            query["flow"] = filter.Flow;
            query["customerId"] = filter.CustomerId;
            query["subjectCpf"] = filter.SubjectCpf;
            query["from"] = filter.From;
            query["to"] = filter.To;
            query["subaccountId"] = filter.SubaccountId;
            query["environment"] = filter.Environment;
        }

        return SendAsync<SessionPage>(HttpMethod.Get, "/sessions", query: query, idempotent: true, cancellationToken: cancellationToken);
    }

    /// <summary>Closes a session that has not settled. The allowance slot comes back.</summary>
    public async Task<Session> CancelSessionAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var envelope = await SendAsync<Envelope<Session>>(
            HttpMethod.Post, $"/sessions/{Uri.EscapeDataString(sessionId)}/cancel", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return envelope.Data!;
    }

    /// <summary>Signed evidence plus short-lived download links for the artifacts.</summary>
    public async Task<EvidenceBundle> GetEvidenceAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var envelope = await SendAsync<Envelope<EvidenceBundle>>(
            HttpMethod.Get, $"/sessions/{Uri.EscapeDataString(sessionId)}/evidence", idempotent: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return envelope.Data!;
    }

    /// <summary>Published signing keys, retired ones included, so old evidence still verifies.</summary>
    public async Task<IReadOnlyList<EvidenceKey>> GetEvidenceKeysAsync(CancellationToken cancellationToken = default)
    {
        var envelope = await SendAsync<Envelope<List<EvidenceKey>>>(
            HttpMethod.Get, "/evidence-keys", idempotent: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return envelope.Data ?? new List<EvidenceKey>();
    }

    /// <summary>
    /// Uploads a capture your own app recorded, authenticating with the session's
    /// capture token — the account key never leaves your server. Only video/webm
    /// and video/mp4 are accepted, up to 16 MiB and 24 seconds.
    ///
    /// Prefer the hosted page when you can: it already runs the quality checks
    /// that keep a useless recording from spending an attempt.
    /// </summary>
    public async Task<CaptureResult> SubmitCaptureAsync(
        string sessionId,
        string captureToken,
        byte[] video,
        string videoMime = "video/webm",
        string videoFilename = "challenge.webm",
        string? channel = null,
        string? telemetryJson = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(captureToken))
        {
            throw new BiometricsException(0, "UNAUTHORIZED", "a capture token is required");
        }
        if (video.Length == 0)
        {
            throw new BiometricsException(0, "VALIDATION", "the video is empty");
        }

        using var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(video);
        file.Headers.ContentType = new MediaTypeHeaderValue(videoMime);
        form.Add(file, "video", videoFilename);
        if (telemetryJson is not null) form.Add(new StringContent(telemetryJson), "telemetry");
        if (channel is not null) form.Add(new StringContent(channel), "channel");

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_options.BaseUrl.TrimEnd('/')}/sessions/{Uri.EscapeDataString(sessionId)}/captures")
        {
            Content = form,
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd($"catalisa-biometrics-dotnet/{Version}");
        // The capture token authenticates this call on its own.
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", captureToken);

        var envelope = await ReadAsync<Envelope<CaptureResult>>(request, cancellationToken).ConfigureAwait(false);

        return envelope.Data!;
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        IDictionary<string, string?>? query = null,
        object? body = null,
        IDictionary<string, string>? headers = null,
        bool idempotent = false,
        CancellationToken cancellationToken = default)
    {
        var url = _options.BaseUrl.TrimEnd('/') + path;
        if (query is not null)
        {
            var pairs = query
                .Where(pair => !string.IsNullOrEmpty(pair.Value))
                .Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value!)}")
                .ToArray();
            if (pairs.Length > 0) url += "?" + string.Join("&", pairs);
        }

        var payload = body is null ? null : JsonSerializer.Serialize(body, Json);

        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd($"catalisa-biometrics-dotnet/{Version}");
            if (!string.IsNullOrEmpty(_options.AccessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.AccessToken);
            }
            else
            {
                request.Headers.Add("X-API-Key", _options.ApiKey);
            }
            if (!string.IsNullOrEmpty(_options.SubaccountId))
            {
                request.Headers.Add("X-Subaccount-Id", _options.SubaccountId);
            }
            if (headers is not null)
            {
                foreach (var header in headers) request.Headers.Add(header.Key, header.Value);
            }
            if (payload is not null)
            {
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            }

            try
            {
                return await ReadAsync<T>(request, cancellationToken).ConfigureAwait(false);
            }
            catch (BiometricsException e)
            {
                // A 429 is always safe to retry: the rate limiter refuses before the
                // handler runs, so nothing was done.
                // 429 by number: the older .NET has no HttpStatusCode.TooManyRequests.
                var retryable = e.Status == 429
                    || (idempotent && (e.Status >= 500 || e.Status == 0));
                if (!retryable || attempt >= _options.MaxRetries || cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                var wait = Backoff(attempt, e);
                if (_options.Delay is not null)
                {
                    await _options.Delay(wait, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                }
            }
        }
    }

    private async Task<T> ReadAsync<T>(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new BiometricsException(0, "TIMEOUT", $"no answer within {_options.Timeout.TotalSeconds:0.#}s");
        }
        catch (HttpRequestException e)
        {
            throw new BiometricsException(0, "CONNECTION", "connection failed: " + e.Message);
        }

        using (response)
        {
            var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            if ((int)response.StatusCode >= 400)
            {
                throw BiometricsException.FromResponse((int)response.StatusCode, text, name =>
                {
                    if (response.Headers.TryGetValues(name, out var values)) return values.FirstOrDefault();
                    if (response.Content.Headers.TryGetValues(name, out var content)) return content.FirstOrDefault();
                    return null;
                });
            }
            if (string.IsNullOrWhiteSpace(text))
            {
                return default!;
            }
            try
            {
                return JsonSerializer.Deserialize<T>(text, Json)!;
            }
            catch (JsonException e)
            {
                throw new BiometricsException((int)response.StatusCode, "INTERNAL", "unexpected answer: " + e.Message);
            }
        }
    }

    private static TimeSpan Backoff(int attempt, BiometricsException e)
    {
        if (e.RetryAfter is int seconds && seconds > 0)
        {
            return TimeSpan.FromSeconds(Math.Min(seconds, 30));
        }
        var baseMs = 500 * Math.Pow(2, attempt);
        var jitter = Jitter.Next((int)(baseMs / 4));

        return TimeSpan.FromMilliseconds(Math.Min(baseMs + jitter, 8000));
    }

    /// <summary>Disposes the underlying HttpClient.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }

    /// <summary>
    /// Random for the backoff. Not Random.Shared: that arrived in .NET 6 and this
    /// package also targets the older .NET. One instance behind a lock is plenty
    /// for picking milliseconds.
    /// </summary>
    private static class Jitter
    {
        private static readonly Random Source = new();

        public static int Next(int max)
        {
            if (max <= 0) return 0;
            lock (Source) return Source.Next(0, max);
        }
    }

    private sealed class Envelope<T>
    {
        [JsonPropertyName("data")] public T? Data { get; init; }
    }
}

/// <summary>Body of <c>POST /sessions</c>. Flow and Purpose are required.</summary>
public sealed class CreateSessionInput
{
    [JsonPropertyName("flow")] public string Flow { get; init; } = "";

    /// <summary>What you would tell an auditor who asked why this face was processed.</summary>
    [JsonPropertyName("purpose")] public string Purpose { get; init; } = "";

    [JsonPropertyName("legalBasis")] public string? LegalBasis { get; init; }

    /// <summary>Only the HMAC and a mask are stored; the CPF itself never is.</summary>
    [JsonPropertyName("subjectRef")] public SubjectInput? SubjectRef { get; init; }

    [JsonPropertyName("customerId")] public string? CustomerId { get; init; }
    [JsonPropertyName("reference")] public ReferenceInput? Reference { get; init; }
    [JsonPropertyName("providerConfigId")] public string? ProviderConfigId { get; init; }

    /// <summary>Up to 10 free-form labels. Never put a CPF here.</summary>
    [JsonPropertyName("metadata")] public IDictionary<string, string>? Metadata { get; init; }

    /// <summary>Stores the face template on approval. ONBOARDING and ENROLLMENT only.</summary>
    [JsonPropertyName("enrollOnApprove")] public bool? EnrollOnApprove { get; init; }
}

public sealed class SubjectInput
{
    [JsonPropertyName("type")] public string Type { get; init; } = "CPF";
    [JsonPropertyName("value")] public string Value { get; init; } = "";
}

public sealed class ReferenceInput
{
    [JsonPropertyName("source")] public string Source { get; init; } = "";
    [JsonPropertyName("fileId")] public string? FileId { get; init; }
    [JsonPropertyName("templateId")] public string? TemplateId { get; init; }
}

/// <summary>Filters for <see cref="BiometricsClient.ListSessionsAsync"/>.</summary>
public sealed class ListSessionsInput
{
    public int? Page { get; init; }
    public int? PageSize { get; init; }
    public string? Status { get; init; }
    public string? Flow { get; init; }
    public string? CustomerId { get; init; }

    /// <summary>The server computes the HMAC. Prefer CustomerId: this travels in the query string.</summary>
    public string? SubjectCpf { get; init; }

    public string? From { get; init; }
    public string? To { get; init; }
    public string? SubaccountId { get; init; }

    /// <summary>"test" or "live". A subaccount key is sealed into its own world and ignores this.</summary>
    public string? Environment { get; init; }
}
