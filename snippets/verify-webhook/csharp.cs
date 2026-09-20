// Minimal server that receives the Biometrics webhook and verifies the signature.
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
#:sdk Microsoft.NET.Sdk.Web
#:package Catalisa.Biometrics@0.1.0
// A file-based app builds AOT-ready, where reflection-based JSON is off; the SDK uses it.
#:property JsonSerializerIsReflectionEnabledByDefault=true
using System.Text.Json;
using Catalisa.Biometrics;

var keys = JsonSerializer.Deserialize<Dictionary<string, string>>(
    Environment.GetEnvironmentVariable("CATALISA_WEBHOOK_KEYS")!)!;
var verifier = new WebhookVerifier(keys); // tolerance: 5 min

var builder = WebApplication.CreateBuilder();
var app = builder.Build();

app.MapPost("/webhooks/biometrics", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var rawBody = await reader.ReadToEndAsync(); // RAW body: re-encoding it breaks the signature

    try
    {
        var evt = verifier.Verify(name => request.Headers[name].FirstOrDefault(), rawBody);

        // evt.Id is stable: use it for idempotency, a delivery can repeat
        if (evt.Type == WebhookEvents.SessionCompleted)
        {
            Console.WriteLine($"session {evt.Data.GetProperty("sessionId")} → {evt.Data.GetProperty("outcome")}");
        }

        return Results.Ok("ok"); // answer fast; do the work afterwards
    }
    catch (WebhookVerificationException e)
    {
        Console.Error.WriteLine($"webhook rejected: {e.Failure}");
        return Results.BadRequest("invalid signature");
    }
});

app.Run($"http://0.0.0.0:{Environment.GetEnvironmentVariable("PORT") ?? "3000"}");
