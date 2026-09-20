// Maven: io.github.catalisaio:catalisa-biometrics:0.1.0
import app.catalisa.biometrics.BiometricsClient;
import app.catalisa.biometrics.Models;

import java.util.Map;

public class CreateSession {
    public static void main(String[] args) {
        var bio = BiometricsClient.builder()
                .apiKey(System.getenv("CATALISA_API_KEY"))
                .baseUrl(System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", BiometricsClient.DEFAULT_BASE_URL))
                .build();

        var session = bio.createSession(Map.of(
                "flow", Models.Flows.LIVENESS_ONLY,
                "purpose", "abertura de conta",
                "metadata", Map.of("orderId", "123")));

        System.out.println("sessionId: " + session.sessionId());
        System.out.println("captureUrl: " + session.handoff().captureUrl()); // send the person here
    }
}
