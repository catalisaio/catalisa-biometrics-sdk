package app.catalisa.biometrics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Verification of Catalisa Webhooks Engine deliveries:
 *
 * <pre>
 * message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
 * signature = RSA-SHA256 (PKCS#1 v1.5), base64, in x-webhook-signature as "v1=&lt;base64&gt;"
 * key       = the subscription's PUBLIC key, chosen by x-webhook-key-id
 * </pre>
 *
 * <p>The signature is asymmetric: there is no shared secret to leak. The engine
 * does not refuse old deliveries — the receiver enforces the time tolerance, or
 * a captured delivery could be replayed forever.
 */
public final class WebhookVerifier {

    /** Which check refused a delivery. */
    public enum Failure {
        MISSING_HEADERS,
        TIMESTAMP_INVALID,
        TIMESTAMP_OUT_OF_TOLERANCE,
        UNKNOWN_KEY_ID,
        UNSUPPORTED_SIGNATURE_VERSION,
        INVALID_SIGNATURE,
    }

    /** A delivery that failed verification. Answer 400 and do not process the body. */
    public static final class VerificationException extends RuntimeException {
        private final Failure failure;

        VerificationException(Failure failure, String message) {
            super(message);
            this.failure = failure;
        }

        public Failure failure() {
            return failure;
        }
    }

    private final Map<String, String> publicKeys;
    private final Duration tolerance;
    private final Supplier<Instant> now;

    /**
     * @param publicKeys keyId to PEM. Keep a retired key here while deliveries
     *                   signed with it may still arrive.
     */
    public WebhookVerifier(Map<String, String> publicKeys) {
        this(publicKeys, Duration.ofMinutes(5), Instant::now);
    }

    /**
     * @param tolerance {@link Duration#ZERO} disables the timestamp check, which
     *                  allows replay — do not.
     */
    public WebhookVerifier(Map<String, String> publicKeys, Duration tolerance, Supplier<Instant> now) {
        this.publicKeys = Map.copyOf(publicKeys);
        this.tolerance = tolerance;
        this.now = now;
    }

    /**
     * Verifies a delivery and returns the parsed event.
     *
     * <p>Pass the RAW body — the bytes as they arrived. Reading the request into
     * a model and re-serializing it changes them, and the signature will not
     * match.
     *
     * @param header reads one header by name, case-insensitively
     */
    public Models.WebhookEvent verify(Function<String, String> header, String rawBody) {
        String id = header.apply("x-webhook-id");
        String timestamp = header.apply("x-webhook-timestamp");
        String keyId = header.apply("x-webhook-key-id");
        String signature = header.apply("x-webhook-signature");

        if (isBlank(id) || isBlank(timestamp) || isBlank(keyId) || isBlank(signature)) {
            throw fail(Failure.MISSING_HEADERS,
                    "missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature");
        }

        Instant sentAt;
        try {
            sentAt = Instant.parse(timestamp);
        } catch (DateTimeParseException e) {
            throw fail(Failure.TIMESTAMP_INVALID, "x-webhook-timestamp is not an ISO 8601 date");
        }
        if (!tolerance.isZero() && Duration.between(sentAt, now.get()).abs().compareTo(tolerance) > 0) {
            throw fail(Failure.TIMESTAMP_OUT_OF_TOLERANCE, "delivery is outside the time tolerance (possible replay)");
        }
        if (!signature.startsWith("v1=")) {
            throw fail(Failure.UNSUPPORTED_SIGNATURE_VERSION, "unsupported signature version (expected v1=)");
        }
        String pem = publicKeys.get(keyId);
        if (pem == null) {
            throw fail(Failure.UNKNOWN_KEY_ID, "no public key for this x-webhook-key-id");
        }

        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(signature.substring(3));
        } catch (IllegalArgumentException e) {
            throw fail(Failure.INVALID_SIGNATURE, "invalid signature");
        }

        boolean valid;
        try {
            PublicKey key = readPublicKey(pem, "RSA");
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update((id + "\n" + timestamp + "\n" + rawBody).getBytes(StandardCharsets.UTF_8));
            valid = verifier.verify(raw);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw fail(Failure.UNKNOWN_KEY_ID, "the public key for this keyId is not readable");
        }
        if (!valid) {
            throw fail(Failure.INVALID_SIGNATURE, "invalid signature");
        }

        try {
            return BiometricsClient.MAPPER.readValue(rawBody, Models.WebhookEvent.class);
        } catch (IOException e) {
            throw fail(Failure.INVALID_SIGNATURE, "the signed body is not valid JSON: " + e.getMessage());
        }
    }

    static PublicKey readPublicKey(String pem, String algorithm) throws GeneralSecurityException {
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);

        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }

    private static VerificationException fail(Failure failure, String message) {
        return new VerificationException(failure, message);
    }
}
