// Reads the session envelope (Java 17+, JDK only). Run: SESSION_ID=… java java.java
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class GetSession {
    public static void main(String[] args) throws Exception {
        String baseUrl = System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1");
        String id = URLEncoder.encode(System.getenv("SESSION_ID"), StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/sessions/" + id))
            .header("X-API-Key", System.getenv("CATALISA_API_KEY"))
            .GET().build();
        HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());

        if (res.statusCode() == 404) { System.err.println("Session not found"); System.exit(1); }
        if (res.statusCode() != 200) { System.err.println("Error " + res.statusCode() + ": " + res.body()); System.exit(1); }
        // Parse with your JSON library; "status" and "decision.outcome" drive your flow.
        var status = Pattern.compile("\"status\"\\s*:\\s*\"([A-Z_]+)\"").matcher(res.body());
        System.out.println("status: " + (status.find() ? status.group(1) : "?"));
        var outcome = Pattern.compile("\"outcome\"\\s*:\\s*\"([A-Z_]+)\"").matcher(res.body());
        if (outcome.find()) System.out.println("decision: " + outcome.group(1));
    }
}
