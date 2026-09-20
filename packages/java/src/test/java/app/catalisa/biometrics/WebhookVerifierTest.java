package app.catalisa.biometrics;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebhookVerifierTest {

    private final JsonNode vectors = Vectors.load();

    private JsonNode webhook() {
        return vectors.get("webhook");
    }

    private Map<String, String> headers(String overrideName, String overrideValue) {
        Map<String, String> headers = new HashMap<>();
        webhook().get("headers").fields()
                .forEachRemaining(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
        if (overrideName != null) {
            headers.put(overrideName, overrideValue);
        }
        return headers;
    }

    private static Function<String, String> reader(Map<String, String> headers) {
        return name -> headers.get(name);
    }

    private WebhookVerifier verifier(Instant at, Duration tolerance) {
        Map<String, String> keys = new HashMap<>();
        webhook().get("keys").fields().forEachRemaining(entry -> keys.put(entry.getKey(), entry.getValue().asText()));

        return new WebhookVerifier(keys, tolerance, () -> at);
    }

    private WebhookVerifier verifier() {
        return verifier(Instant.parse(webhook().get("now").asText()), Duration.ofMinutes(5));
    }

    @Test
    void acceptsAGenuineDelivery() {
        var event = verifier().verify(reader(headers(null, null)), webhook().get("body").asText());

        assertFalse(event.id().isEmpty());
        assertEquals(Models.WebhookEvents.SESSION_COMPLETED, event.type());
    }

    @Test
    void rejectsATamperedBody() {
        var error = assertThrows(WebhookVerifier.VerificationException.class,
                () -> verifier().verify(reader(headers(null, null)), webhook().get("tamperedBody").asText()));

        assertEquals(WebhookVerifier.Failure.INVALID_SIGNATURE, error.failure());
    }

    @Test
    void rejectsAnOldDelivery() {
        // The engine does not refuse old deliveries — the receiver does, or a
        // captured delivery could be replayed forever.
        var sentAt = Instant.parse(webhook().get("headers").get("x-webhook-timestamp").asText());
        var late = sentAt.plus(Duration.ofMinutes(10));

        var error = assertThrows(WebhookVerifier.VerificationException.class,
                () -> verifier(late, Duration.ofMinutes(5)).verify(reader(headers(null, null)), webhook().get("body").asText()));
        assertEquals(WebhookVerifier.Failure.TIMESTAMP_OUT_OF_TOLERANCE, error.failure());

        var event = verifier(late, Duration.ofHours(1))
                .verify(reader(headers(null, null)), webhook().get("body").asText());
        assertFalse(event.id().isEmpty());
    }

    @Test
    void rejectsMissingHeadersUnknownKeyAndAnotherVersion() {
        var body = webhook().get("body").asText();

        var bare = assertThrows(WebhookVerifier.VerificationException.class,
                () -> verifier().verify(name -> null, body));
        assertEquals(WebhookVerifier.Failure.MISSING_HEADERS, bare.failure());

        var unknown = assertThrows(WebhookVerifier.VerificationException.class,
                () -> verifier().verify(reader(headers("x-webhook-key-id", "whk_not_mine")), body));
        assertEquals(WebhookVerifier.Failure.UNKNOWN_KEY_ID, unknown.failure());

        var version = assertThrows(WebhookVerifier.VerificationException.class,
                () -> verifier().verify(reader(headers("x-webhook-signature", "v2=abc")), body));
        assertEquals(WebhookVerifier.Failure.UNSUPPORTED_SIGNATURE_VERSION, version.failure());
    }

    @Test
    void verifiesEvidenceOffline() {
        var evidence = vectors.get("evidence");
        List<Models.EvidenceKey> keys = new ArrayList<>();
        evidence.get("evidenceKeysResponse").get("data").forEach(node ->
                keys.add(BiometricsClient.MAPPER.convertValue(node, Models.EvidenceKey.class)));
        var signature = BiometricsClient.MAPPER.convertValue(
                evidence.get("evidence").get("signature"), Models.EvidenceSignature.class);
        var sessionId = evidence.get("sessionId").asText();
        var attempt = evidence.get("attempt").asInt();
        var bundleHash = evidence.get("evidence").get("bundleHash").asText();

        var ok = Evidence.verify(sessionId, attempt, bundleHash, signature, keys);
        assertTrue(ok.valid());
        assertFalse(ok.unknownKey());

        // Any change to what was signed breaks it — that is the whole point.
        assertFalse(Evidence.verify(sessionId, attempt + 1, bundleHash, signature, keys).valid());
        assertFalse(Evidence.verify(sessionId, attempt, "0000", signature, keys).valid());

        var unknownKey = new Models.EvidenceSignature(
                signature.alg(), "ev-unknown", signature.signedAt(), signature.value());
        var unknown = Evidence.verify(sessionId, attempt, bundleHash, unknownKey, keys);
        assertTrue(unknown.unknownKey());
        assertFalse(unknown.valid());
    }
}
