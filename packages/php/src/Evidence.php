<?php

declare(strict_types=1);

namespace Catalisa\Biometrics;

/**
 * OFFLINE verification of the signed evidence, without depending on Catalisa:
 *
 *   message   = "{sessionId}|{attempt}|{bundleHash}|{signedAt}"
 *   signature = Ed25519 (RFC 8032) with the organization's key, base64
 *   key       = GET /evidence-keys → publicKeyPem of the signature's keyId
 *
 * This is what lets a third party — an auditor, a court — confirm years later
 * that the bundle is the one Catalisa signed.
 */
final class Evidence
{
    /**
     * The 32 raw bytes of an Ed25519 key inside a PEM. The DER wrapper
     * (SubjectPublicKeyInfo) is a fixed 12-byte header followed by the key, which
     * is why taking the tail is enough — and why a key of another kind, being a
     * different length, is refused here.
     */
    private static function rawKeyFromPem(string $pem): ?string
    {
        if (!preg_match('/-----BEGIN PUBLIC KEY-----(.+)-----END PUBLIC KEY-----/s', $pem, $m)) {
            return null;
        }
        $der = base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
        if ($der === false || strlen($der) !== 44) {
            return null;
        }

        return substr($der, -SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
    }

    /** The exact string that was signed. */
    public static function message(string $sessionId, int $attempt, string $bundleHash, string $signedAt): string
    {
        return "{$sessionId}|{$attempt}|{$bundleHash}|{$signedAt}";
    }

    /**
     * @param array<string,mixed>              $signature the envelope's evidence.signature
     * @param array<int,array<string,mixed>>   $keys      what GET /evidence-keys answered
     * @return array{valid:bool,keyId:string,unknownKey:bool,retiredAt:?string}
     */
    public static function verify(string $sessionId, int $attempt, string $bundleHash, array $signature, array $keys): array
    {
        $keyId = (string) ($signature['keyId'] ?? '');
        $out = ['valid' => false, 'keyId' => $keyId, 'unknownKey' => false, 'retiredAt' => null];

        $key = null;
        foreach ($keys as $candidate) {
            if (($candidate['keyId'] ?? null) === $keyId) {
                $key = $candidate;
                break;
            }
        }
        if ($key === null) {
            $out['unknownKey'] = true;

            return $out;
        }
        $out['retiredAt'] = $key['retiredAt'] ?? null;
        if (($signature['alg'] ?? null) !== 'Ed25519') {
            return $out;
        }
        $raw = base64_decode((string) ($signature['value'] ?? ''), true);
        if ($raw === false) {
            return $out;
        }
        $publicKey = self::rawKeyFromPem((string) ($key['publicKeyPem'] ?? ''));
        if ($publicKey === null || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return $out;
        }
        $message = self::message($sessionId, $attempt, $bundleHash, (string) ($signature['signedAt'] ?? ''));
        // Ed25519 signs the message itself, with no separate digest step, so
        // openssl_verify (which always takes a digest algorithm) cannot do it.
        // libsodium ships with PHP and does exactly this one thing.
        $out['valid'] = sodium_crypto_sign_verify_detached($raw, $message, $publicKey);

        return $out;
    }
}
