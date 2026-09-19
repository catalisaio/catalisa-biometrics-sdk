// Receives the Biometrics webhook and verifies the signature (.NET 8+, BCL only). With .NET 10: dotnet run csharp.cs
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var publicKeys = new Dictionary<string, string>();
using (var doc = JsonDocument.Parse(Environment.GetEnvironmentVariable("CATALISA_WEBHOOK_KEYS")!))
    foreach (var p in doc.RootElement.EnumerateObject()) publicKeys[p.Name] = p.Value.GetString()!;

var listener = new HttpListener();
listener.Prefixes.Add($"http://*:{Environment.GetEnvironmentVariable("PORT") ?? "3000"}/webhooks/biometrics/");
listener.Start();

while (true)
{
    var ctx = await listener.GetContextAsync();
    using var ms = new MemoryStream();
    await ctx.Request.InputStream.CopyToAsync(ms);
    var rawBody = ms.ToArray(); // RAW body
    var valid = Verify(rawBody, ctx.Request.Headers);
    if (valid) Console.WriteLine("webhook ok: " + Encoding.UTF8.GetString(rawBody)); // idempotency: the body's "id"
    ctx.Response.StatusCode = valid ? 200 : 400;
    ctx.Response.Close();
}

bool Verify(byte[] body, NameValueCollection h)
{
    string? id = h["x-webhook-id"], timestamp = h["x-webhook-timestamp"], keyId = h["x-webhook-key-id"], signature = h["x-webhook-signature"];
    if (id is null || timestamp is null || keyId is null || signature is null || !signature.StartsWith("v1=")) return false;
    if (!DateTimeOffset.TryParse(timestamp, out var sentAt) || Math.Abs((DateTimeOffset.UtcNow - sentAt).TotalSeconds) > 300) return false;
    if (!publicKeys.TryGetValue(keyId, out var pem)) return false;
    using var rsa = RSA.Create();
    rsa.ImportFromPem(pem);
    var message = Encoding.UTF8.GetBytes($"{id}\n{timestamp}\n").Concat(body).ToArray();
    try { return rsa.VerifyData(message, Convert.FromBase64String(signature[3..]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
    catch (FormatException) { return false; }
}
