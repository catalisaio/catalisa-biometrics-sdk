// Reads the session envelope (.NET 8+, BCL only). With .NET 10: SESSION_ID=… dotnet run csharp.cs
using System.Text.Json;

var baseUrl = Environment.GetEnvironmentVariable("CATALISA_BIOMETRICS_URL") ?? "https://api.biometrics.catalisa.app/v1";
var id = Uri.EscapeDataString(Environment.GetEnvironmentVariable("SESSION_ID")!);
using var http = new HttpClient();
http.DefaultRequestHeaders.Add("X-API-Key", Environment.GetEnvironmentVariable("CATALISA_API_KEY"));

var res = await http.GetAsync($"{baseUrl}/sessions/{id}");
if (!res.IsSuccessStatusCode)
{
    Console.Error.WriteLine($"Error {(int)res.StatusCode}");
    return 1;
}
using var body = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
var session = body.RootElement.GetProperty("data");
Console.WriteLine($"status: {session.GetProperty("status").GetString()}");
if (session.GetProperty("decision").ValueKind == JsonValueKind.Object)
{
    Console.WriteLine($"decision: {session.GetProperty("decision").GetProperty("outcome").GetString()}");
    foreach (var c in session.GetProperty("checks").EnumerateArray())
        Console.WriteLine($" - {c.GetProperty("kind")}: {c.GetProperty("status")} (score {c.GetProperty("score")} / threshold {c.GetProperty("threshold")})");
}
return 0;
