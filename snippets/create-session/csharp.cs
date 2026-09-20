// dotnet add package Catalisa.Biometrics  (.NET 10 runs this file directly: dotnet run csharp.cs)
#:package Catalisa.Biometrics@0.1.0
// A file-based app builds AOT-ready, where reflection-based JSON is off; the SDK uses it.
#:property JsonSerializerIsReflectionEnabledByDefault=true
using Catalisa.Biometrics;

using var bio = new BiometricsClient(new BiometricsOptions
{
    ApiKey = Environment.GetEnvironmentVariable("CATALISA_API_KEY")!,
    BaseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? BiometricsClient.DefaultBaseUrl,
});

var session = await bio.CreateSessionAsync(new CreateSessionInput
{
    Flow = Flows.LivenessOnly,
    Purpose = "abertura de conta",
    Metadata = new Dictionary<string, string> { ["orderId"] = "123" },
});

Console.WriteLine($"sessionId: {session.SessionId}");
Console.WriteLine($"captureUrl: {session.Handoff!.CaptureUrl}"); // send the person here
