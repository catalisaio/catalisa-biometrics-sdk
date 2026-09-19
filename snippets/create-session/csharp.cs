// Creates a liveness session (.NET 8+, BCL only). With .NET 10: dotnet run csharp.cs
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

var baseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? "https://api.biometrics.catalisa.app/v1";
using var http = new HttpClient();
http.DefaultRequestHeaders.Add("X-API-Key", Environment.GetEnvironmentVariable("CATALISA_API_KEY"));

var payload = new JsonObject
{
    ["flow"] = "LIVENESS_ONLY",
    ["purpose"] = "abertura de conta",
    ["metadata"] = new JsonObject { ["orderId"] = "123" },
};
var res = await http.PostAsync($"{baseUrl}/sessions", new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json"));
using var body = JsonDocument.Parse(await res.Content.ReadAsStringAsync());

if ((int)res.StatusCode != 201)
{
    Console.Error.WriteLine($"Error {(int)res.StatusCode}: {body.RootElement}");
    return 1;
}
var data = body.RootElement.GetProperty("data");
Console.WriteLine($"sessionId: {data.GetProperty("sessionId").GetString()}");
Console.WriteLine($"captureUrl: {data.GetProperty("handoff").GetProperty("captureUrl").GetString()}");
return 0;
