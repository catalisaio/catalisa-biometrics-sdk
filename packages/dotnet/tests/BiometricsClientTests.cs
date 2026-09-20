using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Catalisa.Biometrics.Tests;

/// <summary>A transport that answers from a queue and records what went out.</summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    private readonly Queue<(int Status, string Body, IDictionary<string, string>? Headers)> _answers = new();

    public List<HttpRequestMessage> Requests { get; } = new();
    public List<string> Bodies { get; } = new();

    public FakeHandler Answer(int status, string body, IDictionary<string, string>? headers = null)
    {
        _answers.Enqueue((status, body, headers));
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        Bodies.Add(request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken));

        var (status, body, headers) = _answers.Count > 0
            ? _answers.Dequeue()
            : (500, "{\"error\":\"INTERNAL\"}", null);

        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        if (headers is not null)
        {
            foreach (var header in headers) response.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return response;
    }
}

public class BiometricsClientTests
{
    private static BiometricsClient Client(FakeHandler handler, string? subaccountId = null, int maxRetries = 2)
        => new(new BiometricsOptions
        {
            ApiKey = "bio_test_key",
            BaseUrl = "https://api.example/v1",
            SubaccountId = subaccountId,
            MaxRetries = maxRetries,
            Handler = handler,
            Delay = (_, _) => Task.CompletedTask,
        });

    [Fact]
    public void ACredentialIsRequired()
    {
        Assert.Throws<ArgumentException>(() => new BiometricsClient(new BiometricsOptions()));
        using var withJwt = new BiometricsClient(new BiometricsOptions { AccessToken = "jwt" });
        Assert.NotNull(withJwt);
    }

    [Fact]
    public async Task CreateSessionSendsTheKeyAndReturnsTheEnvelope()
    {
        var handler = new FakeHandler().Answer(201,
            """{"data":{"sessionId":"s1","status":"SESSION_OPEN","environment":"test","provider":"MOCK","handoff":{"captureUrl":"https://capture/x","captureToken":"tok"}}}""");
        using var client = Client(handler, subaccountId: "sub-1");

        var session = await client.CreateSessionAsync(
            new CreateSessionInput
            {
                Flow = Flows.LivenessOnly,
                Purpose = "abertura de conta",
                Metadata = new Dictionary<string, string> { ["orderId"] = "123" },
            },
            idempotencyKey: "idem-1");

        var request = handler.Requests[0];
        Assert.Equal("https://api.example/v1/sessions", request.RequestUri!.ToString());
        Assert.Equal("bio_test_key", request.Headers.GetValues("X-API-Key").First());
        Assert.Equal("sub-1", request.Headers.GetValues("X-Subaccount-Id").First());
        Assert.Equal("idem-1", request.Headers.GetValues("Idempotency-Key").First());
        Assert.Contains("\"flow\":\"LIVENESS_ONLY\"", handler.Bodies[0]);
        Assert.Equal("s1", session.SessionId);
        Assert.True(session.IsSandbox);
        Assert.Equal("https://capture/x", session.Handoff!.CaptureUrl);
    }

    [Fact]
    public async Task QuotaAndSuspensionKeepTheirCodeAndNumbers()
    {
        var handler = new FakeHandler().Answer(402,
            """{"error":"PAYMENT_REQUIRED","message":"cota","details":{"code":"QUOTA_EXCEEDED","used":100,"monthlyQuota":100}}""");
        using var client = Client(handler);

        var error = await Assert.ThrowsAsync<BiometricsException>(() =>
            client.CreateSessionAsync(new CreateSessionInput { Flow = Flows.LivenessOnly, Purpose = "x" }));

        Assert.True(error.IsQuotaExceeded);
        Assert.False(error.IsSubaccountSuspended);
        Assert.Equal(100, error.Details["used"].GetInt32());

        var suspended = new FakeHandler().Answer(403,
            """{"error":"FORBIDDEN","message":"suspensa","details":{"code":"SUBACCOUNT_SUSPENDED","reason":"inadimplência"}}""");
        using var other = Client(suspended);

        var second = await Assert.ThrowsAsync<BiometricsException>(() =>
            other.CreateSessionAsync(new CreateSessionInput { Flow = Flows.LivenessOnly, Purpose = "x" }));

        Assert.True(second.IsSubaccountSuspended);
        Assert.Equal("inadimplência", second.Details["reason"].GetString());
    }

    [Fact]
    public async Task AnHtmlErrorPageStillYieldsAUsableCode()
    {
        // A proxy in front of the API can answer HTML. The caller still needs a code.
        var handler = new FakeHandler().Answer(502, "<html>502</html>");
        using var client = Client(handler, maxRetries: 0);

        var error = await Assert.ThrowsAsync<BiometricsException>(() => client.GetSessionAsync("s1"));

        Assert.Equal("INTERNAL", error.ErrorCode);
        Assert.True(error.IsTransient);
    }

    [Fact]
    public async Task ReadsRetryButSessionCreationDoesNot()
    {
        var reads = new FakeHandler()
            .Answer(500, """{"error":"INTERNAL"}""")
            .Answer(200, """{"data":{"sessionId":"s1","status":"APPROVED"}}""");
        using var readClient = Client(reads);

        var session = await readClient.GetSessionAsync("s1");
        Assert.Equal(SessionStatuses.Approved, session.Status);
        Assert.Equal(2, reads.Requests.Count);

        // Creating twice would open two sessions and spend the allowance twice.
        var writes = new FakeHandler()
            .Answer(500, """{"error":"INTERNAL"}""")
            .Answer(201, """{"data":{"sessionId":"s2"}}""");
        using var writeClient = Client(writes);

        await Assert.ThrowsAsync<BiometricsException>(() =>
            writeClient.CreateSessionAsync(new CreateSessionInput { Flow = Flows.LivenessOnly, Purpose = "x" }));
        Assert.Single(writes.Requests);
    }

    [Fact]
    public async Task RateLimitIsRetriedEvenOnCreation()
    {
        // The rate limiter refuses before the handler runs: nothing was done.
        var handler = new FakeHandler()
            .Answer(429, """{"error":"RATE_LIMITED"}""", new Dictionary<string, string> { ["Retry-After"] = "0" })
            .Answer(201, """{"data":{"sessionId":"s3"}}""");
        using var client = Client(handler);

        var session = await client.CreateSessionAsync(new CreateSessionInput { Flow = Flows.LivenessOnly, Purpose = "x" });

        Assert.Equal("s3", session.SessionId);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ListSendsPaginationAndFilters()
    {
        var handler = new FakeHandler().Answer(200, """{"data":[],"meta":{"total":0}}""");
        using var client = Client(handler);

        await client.ListSessionsAsync(new ListSessionsInput
        {
            Page = 2,
            PageSize = 50,
            Status = SessionStatuses.Approved,
            Environment = Environments.Test,
        });

        var url = handler.Requests[0].RequestUri!.ToString();
        Assert.Contains("page%5Bnumber%5D=2", url);
        Assert.Contains("page%5Bsize%5D=50", url);
        Assert.Contains("status=APPROVED", url);
        Assert.Contains("environment=test", url);
    }

    [Fact]
    public async Task SubmitCaptureUsesTheCaptureTokenNotTheApiKey()
    {
        var handler = new FakeHandler().Answer(200,
            """{"data":{"sessionId":"s1","status":"RETRY_ALLOWED","attempt":1,"maxAttempts":3,"reasons":["quality.too_dark"]}}""");
        using var client = Client(handler);

        var result = await client.SubmitCaptureAsync("s1", "capture-token", Encoding.UTF8.GetBytes("webm-bytes"), channel: "SDK");

        var request = handler.Requests[0];
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("capture-token", request.Headers.Authorization.Parameter);
        Assert.False(request.Headers.Contains("X-API-Key"));
        Assert.Contains("webm-bytes", handler.Bodies[0]);
        Assert.Equal(SessionStatuses.RetryAllowed, result.Status);
        Assert.Equal("quality.too_dark", Assert.Single(result.Reasons));
    }

    [Fact]
    public async Task SubmitCaptureRefusesAnEmptyVideoBeforeTheNetwork()
    {
        var handler = new FakeHandler();
        using var client = Client(handler);

        await Assert.ThrowsAsync<BiometricsException>(() => client.SubmitCaptureAsync("s1", "tok", Array.Empty<byte>()));
        await Assert.ThrowsAsync<BiometricsException>(() => client.SubmitCaptureAsync("s1", "", Encoding.UTF8.GetBytes("x")));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void TerminalStatusesAreTheOnesThatNeverChange()
    {
        Assert.True(SessionStatuses.IsTerminal(SessionStatuses.Approved));
        Assert.True(SessionStatuses.IsTerminal(SessionStatuses.Cancelled));
        Assert.False(SessionStatuses.IsTerminal(SessionStatuses.RetryAllowed));
        Assert.False(SessionStatuses.IsTerminal(SessionStatuses.SessionOpen));
    }
}
