package app.catalisa.biometrics;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

/**
 * OFFLINE verification of the signed evidence, without calling Catalisa:
 *
 * <pre>
 * message   = "{sessionId}|{attempt}|{bundleHash}|{signedAt}"
 * signature = Ed25519 (RFC 8032), base64
 * key       = GET /evidence-keys, by the signature's keyId
 * </pre>
 *
 * <p>This is what lets a third party — an auditor, a court — confirm years later
 * that the bundle is the one Catalisa signed. Java has had Ed25519 since 15, so
 * nothing beyond the JDK is needed here.
 */
public final class Evidence {

    private Evidence() {
    }

    /** The outcome of checking a signature offline. */
    public record Verification(boolean valid, String keyId, boolean unknownKey, String retiredAt) {
    }

    /** The exact string that was signed. */
    public static String message(String sessionId, int attempt, String bundleHash, String signedAt) {
        return sessionId + "|" + attempt + "|" + bundleHash + "|" + signedAt;
    }

    public static Verification verify(String sessionId, int attempt, String bundleHash,
                                      Models.EvidenceSignature signature, List<Models.EvidenceKey> keys) {
        Models.EvidenceKey key = keys.stream()
                .filter(candidate -> candidate.keyId().equals(signature.keyId()))
                .findFirst()
                .orElse(null);
        if (key == null) {
            return new Verification(false, signature.keyId(), true, null);
        }
        if (!"Ed25519".equals(signature.alg())) {
            return new Verification(false, signature.keyId(), false, key.retiredAt());
        }

        try {
            PublicKey publicKey = WebhookVerifier.readPublicKey(key.publicKeyPem(), "Ed25519");
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(message(sessionId, attempt, bundleHash, signature.signedAt()).getBytes(StandardCharsets.UTF_8));
            boolean valid = verifier.verify(Base64.getDecoder().decode(signature.value()));

            return new Verification(valid, signature.keyId(), false, key.retiredAt());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return new Verification(false, signature.keyId(), false, key.retiredAt());
        }
    }
}
