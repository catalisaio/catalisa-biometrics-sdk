#:package Catalisa.Biometrics@0.1.0
// A file-based app builds AOT-ready, where reflection-based JSON is off; the SDK uses it.
#:property JsonSerializerIsReflectionEnabledByDefault=true
using Catalisa.Biometrics;

using var bio = new BiometricsClient(new BiometricsOptions
{
    ApiKey = Environment.GetEnvironmentVariable("CATALISA_API_KEY")!,
    BaseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? BiometricsClient.DefaultBaseUrl,
    // organization key acting on behalf of the subaccount
    SubaccountId = Environment.GetEnvironmentVariable("CATALISA_SUBACCOUNT_ID"),
});

try
{
    var session = await bio.CreateSessionAsync(new CreateSessionInput { Flow = Flows.LivenessOnly, Purpose = "abertura de conta" });
    Console.WriteLine($"ok: {session.Handoff!.CaptureUrl}");
}
catch (BiometricsException e) when (e.IsQuotaExceeded) // 402
{
    Console.WriteLine($"blocked: {e.ErrorCode} — monthly quota used ({e.Details["used"]}/{e.Details["monthlyQuota"]})");
}
catch (BiometricsException e) when (e.IsSubaccountSuspended) // 403
{
    Console.WriteLine($"blocked: {e.ErrorCode} — subaccount suspended");
}
catch (BiometricsException e) when (e.Status == 429) // the SDK already retried
{
    Console.WriteLine($"rate limited; retry in {e.RetryAfter ?? 1} s");
}
catch (BiometricsException e)
{
    Console.Error.WriteLine($"error {e.Status}: {e.ErrorCode} (requestId {e.RequestId})");
    return 1;
}

return 0;
