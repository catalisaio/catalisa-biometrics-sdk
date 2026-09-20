import app.catalisa.biometrics.BiometricsClient;
import app.catalisa.biometrics.BiometricsException;
import app.catalisa.biometrics.Models;

import java.util.Map;

public class HandleErrors {
    public static void main(String[] args) {
        var bio = BiometricsClient.builder()
                .apiKey(System.getenv("CATALISA_API_KEY"))
                .baseUrl(System.getenv().getOrDefault("CATALISA_BIOMETRICS_URL", BiometricsClient.DEFAULT_BASE_URL))
                // organization key acting on behalf of the subaccount
                .subaccountId(System.getenv("CATALISA_SUBACCOUNT_ID"))
                .build();

        try {
            var session = bio.createSession(Map.of("flow", Models.Flows.LIVENESS_ONLY, "purpose", "abertura de conta"));
            System.out.println("ok: " + session.handoff().captureUrl());
        } catch (BiometricsException e) {
            if (e.isQuotaExceeded()) { // 402
                System.out.printf("blocked: %s — monthly quota used (%s/%s)%n",
                        e.code(), e.details().get("used"), e.details().get("monthlyQuota"));
            } else if (e.isSubaccountSuspended()) { // 403
                System.out.printf("blocked: %s — subaccount suspended%n", e.code());
            } else if (e.status() == 429) { // the SDK already retried
                System.out.printf("rate limited; retry in %s s%n", e.retryAfter() == null ? 1 : e.retryAfter());
            } else {
                System.err.printf("error %d: %s (requestId %s)%n", e.status(), e.code(), e.requestId());
                System.exit(1);
            }
        }
    }
}
