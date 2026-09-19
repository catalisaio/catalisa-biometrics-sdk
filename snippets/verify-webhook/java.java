// Receives the Biometrics webhook and verifies the signature (Java 17+, JDK only). Run: java java.java
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----\n…"}
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class WebhookServer {
    static final Map<String, PublicKey> PUBLIC_KEYS = new HashMap<>();

    public static void main(String[] args) throws Exception {
        // keyId → PEM map (use your JSON library; a regex here to avoid dependencies).
        var m = Pattern.compile("\"(whk_[^\"]+)\"\\s*:\\s*\"([^\"]+)\"").matcher(System.getenv("CATALISA_WEBHOOK_KEYS"));
        while (m.find()) PUBLIC_KEYS.put(m.group(1), publicKey(m.group(2).replace("\\n", "\n")));

        var server = HttpServer.create(new InetSocketAddress(Integer.parseInt(System.getenv().getOrDefault("PORT", "3000"))), 0);
        server.createContext("/webhooks/biometrics", exchange -> {
            byte[] rawBody = exchange.getRequestBody().readAllBytes(); // RAW body
            var h = exchange.getRequestHeaders();
            boolean valid = verify(rawBody, h.getFirst("x-webhook-id"), h.getFirst("x-webhook-timestamp"),
                                   h.getFirst("x-webhook-key-id"), h.getFirst("x-webhook-signature"));
            if (valid) System.out.println("webhook ok: " + new String(rawBody, StandardCharsets.UTF_8));
            // Idempotency: use the body's "id", not the x-webhook-id header.
            exchange.sendResponseHeaders(valid ? 200 : 400, -1);
            exchange.close();
        });
        server.start();
    }

    static boolean verify(byte[] body, String id, String timestamp, String keyId, String signature) {
        try {
            if (id == null || timestamp == null || keyId == null || signature == null || !signature.startsWith("v1=")) return false;
            if (Duration.between(Instant.parse(timestamp), Instant.now()).abs().getSeconds() > 300) return false;
            PublicKey key = PUBLIC_KEYS.get(keyId);
            if (key == null) return false;
            var verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update((id + "\n" + timestamp + "\n").getBytes(StandardCharsets.UTF_8));
            verifier.update(body);
            return verifier.verify(Base64.getDecoder().decode(signature.substring(3)));
        } catch (Exception e) {
            return false;
        }
    }

    static PublicKey publicKey(String pem) throws Exception {
        String b64 = pem.replaceAll("-----(BEGIN|END) PUBLIC KEY-----|\\s", "");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }
}
