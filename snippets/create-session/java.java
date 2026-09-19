// Creates a liveness session (Java 17+, JDK only). Run: java java.java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;

public class CreateSession {
    public static void main(String[] args) throws Exception {
        String baseUrl = System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1");
        String json = """
            {"flow": "LIVENESS_ONLY", "purpose": "abertura de conta", "metadata": {"orderId": "123"}}
            """;

        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/sessions"))
            .header("X-API-Key", System.getenv("CATALISA_API_KEY"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());

        if (res.statusCode() != 201) {
            System.err.println("Error " + res.statusCode() + ": " + res.body());
            System.exit(1);
        }
        // Use your JSON library (Jackson, Gson...). Only the essentials here:
        System.out.println("sessionId: " + field(res.body(), "sessionId"));
        System.out.println("captureUrl: " + field(res.body(), "captureUrl"));
    }

    static String field(String json, String name) {
        var m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
