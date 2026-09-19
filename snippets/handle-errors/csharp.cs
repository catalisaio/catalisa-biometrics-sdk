// Handles 402 (quota) and 403 (suspended subaccount) when creating a session (.NET 8+, BCL only).
using System.Net;
using System.Text;
using System.Text.Json;

var baseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? "https://api.biometrics.catalisa.app/v1";
using var http = new HttpClient();
http.DefaultRequestHeaders.Add("X-API-Key", Environment.GetEnvironmentVariable("CATALISA_API_KEY"));
http.DefaultRequestHeaders.Add("X-Subaccount-Id", Environment.GetEnvironmentVariable("CATALISA_SUBACCOUNT_ID"));

var json = """{"flow":"LIVENESS_ONLY","purpose":"abertura de conta"}""";
var res = await http.PostAsync($"{baseUrl}/sessions", new StringContent(json, Encoding.UTF8, "application/json"));
using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
var body = doc.RootElement;
var hasDetails = body.TryGetProperty("details", out var details) && details.ValueKind == JsonValueKind.Object;
var code = hasDetails && details.TryGetProperty("code", out var c) ? c.GetString()
    : body.TryGetProperty("error", out var err) ? err.GetString() : "";

switch (res.StatusCode)
{
    case HttpStatusCode.Created:
        Console.WriteLine("ok: " + body.GetProperty("data").GetProperty("handoff").GetProperty("captureUrl").GetString());
        break;
    case HttpStatusCode.PaymentRequired when code == "QUOTA_EXCEEDED":
        Console.WriteLine($"blocked: {code} — monthly quota used ({details.GetProperty("used")}/{details.GetProperty("monthlyQuota")})");
        break;
    case HttpStatusCode.Forbidden when code == "SUBACCOUNT_SUSPENDED":
        Console.WriteLine($"blocked: {code} — subaccount suspended");
        break;
    default:
        Console.Error.WriteLine($"error {(int)res.StatusCode}: {code}");
        return 1;
}
return 0;
