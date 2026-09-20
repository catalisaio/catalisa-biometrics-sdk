#:package Catalisa.Biometrics@0.1.0
// A file-based app builds AOT-ready, where reflection-based JSON is off; the SDK uses it.
#:property JsonSerializerIsReflectionEnabledByDefault=true
using Catalisa.Biometrics;

using var bio = new BiometricsClient(new BiometricsOptions
{
    ApiKey = Environment.GetEnvironmentVariable("CATALISA_API_KEY")!,
    BaseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? BiometricsClient.DefaultBaseUrl,
});

try
{
    var session = await bio.GetSessionAsync(Environment.GetEnvironmentVariable("SESSION_ID")!);
    Console.WriteLine($"status: {session.Status}");
    if (session.Decision is not null)
    {
        var reasons = string.Join(", ", session.Decision.Reasons);
        Console.WriteLine($"decision: {session.Decision.Outcome} {(reasons.Length == 0 ? "(no reasons)" : reasons)}");
        foreach (var check in session.Checks)
        {
            Console.WriteLine($" - {check.Kind}: {check.Status} (score {check.Score} / threshold {check.Threshold})");
        }
    }
}
catch (BiometricsException e) when (e.Status == 404)
{
    Console.WriteLine("Session not found (or owned by another organization)");
}
