// Minimal server that receives the Biometrics webhook and verifies the signature.
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
import app.catalisa.biometrics.Models;
import app.catalisa.biometrics.WebhookVerifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class VerifyWebhook {
    public static void main(String[] args) throws Exception {
        Map<String, String> keys = new ObjectMapper()
                .readValue(System.getenv("CATALISA_WEBHOOK_KEYS"), Map.class);
        var verifier = new WebhookVerifier(keys); // tolerance: 5 min

        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "3000"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/webhooks/biometrics", exchange -> {
            String rawBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8); // RAW body
            byte[] answer;
            int status;
            try {
                var event = verifier.verify(name -> exchange.getRequestHeaders().getFirst(name), rawBody);

                // event.id() is stable: use it for idempotency, a delivery can repeat
                if (Models.WebhookEvents.SESSION_COMPLETED.equals(event.type())) {
                    System.err.println("session " + event.data().get("sessionId") + " → " + event.data().get("outcome"));
                }
                status = 200;
                answer = "ok".getBytes(StandardCharsets.UTF_8); // answer fast; do the work afterwards
            } catch (WebhookVerifier.VerificationException e) {
                System.err.println("webhook rejected: " + e.failure());
                status = 400;
                answer = "invalid signature".getBytes(StandardCharsets.UTF_8);
            }
            exchange.sendResponseHeaders(status, answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });

        server.start();
    }
}
