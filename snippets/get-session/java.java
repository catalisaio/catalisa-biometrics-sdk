import app.catalisa.biometrics.BiometricsClient;
import app.catalisa.biometrics.BiometricsException;

public class GetSession {
    public static void main(String[] args) {
        var bio = BiometricsClient.builder()
                .apiKey(System.getenv("CATALISA_API_KEY"))
                .baseUrl(System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", BiometricsClient.DEFAULT_BASE_URL))
                .build();

        try {
            var session = bio.getSession(System.getenv("SESSION_ID"));
            System.out.println("status: " + session.status());
            if (session.decision() != null) {
                var reasons = String.join(", ", session.decision().reasons());
                System.out.println("decision: " + session.decision().outcome() + " " + (reasons.isEmpty() ? "(no reasons)" : reasons));
                session.checks().forEach(check -> System.out.printf(" - %s: %s (score %s / threshold %s)%n",
                        check.kind(), check.status(), check.score(), check.threshold()));
            }
        } catch (BiometricsException e) {
            if (e.status() != 404) throw e;
            System.out.println("Session not found (or owned by another organization)");
        }
    }
}
