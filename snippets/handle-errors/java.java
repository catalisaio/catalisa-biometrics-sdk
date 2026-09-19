// Handles 402 (quota) and 403 (suspended subaccount) when creating a session (Java 17+, JDK only).
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;

public class HandleErrors {
    public static void main(String[] args) throws Exception {
        String baseUrl = System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1");
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/sessions"))
            .header("X-API-Key", System.getenv("CATALISA_API_KEY"))
            .header("X-Subaccount-Id", System.getenv("CATALISA_SUBACCOUNT_ID"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{\"flow\":\"LIVENESS_ONLY\",\"purpose\":\"abertura de conta\"}"))
            .build();
        HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());

        // The specific code is in details.code; the generic one in error.
        var m = Pattern.compile("\"details\"\\s*:\\s*\\{[^}]*\"code\"\\s*:\\s*\"([A-Z_]+)\"").matcher(res.body());
        String code = m.find() ? m.group(1) : "";

        switch (res.statusCode()) {
            case 201 -> System.out.println("ok: session created");
            case 402 -> System.out.println("blocked: " + code + " — subaccount monthly quota reached");
            case 403 -> {
                if (code.equals("SUBACCOUNT_SUSPENDED")) System.out.println("blocked: " + code + " — subaccount suspended");
                else { System.err.println("forbidden: " + res.body()); System.exit(1); }
            }
            default -> { System.err.println("error " + res.statusCode() + ": " + res.body()); System.exit(1); }
        }
    }
}
