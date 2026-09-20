<?php

declare(strict_types=1);

namespace Catalisa\Biometrics;

/**
 * Verification of Catalisa Webhooks Engine deliveries:
 *
 *   message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
 *   signature = RSA-SHA256 (PKCS#1 v1.5), base64, in x-webhook-signature as "v1=<base64>"
 *   key       = the subscription's PUBLIC key, chosen by x-webhook-key-id
 *
 * The signature is asymmetric: there is no shared secret to leak. The engine does
 * not refuse old deliveries — the receiver enforces the time tolerance, or a
 * captured delivery could be replayed forever.
 */
final class WebhookVerifier
{
    public const MISSING_HEADERS = 'MISSING_HEADERS';
    public const TIMESTAMP_INVALID = 'TIMESTAMP_INVALID';
    public const TIMESTAMP_OUT_OF_TOLERANCE = 'TIMESTAMP_OUT_OF_TOLERANCE';
    public const UNKNOWN_KEY_ID = 'UNKNOWN_KEY_ID';
    public const UNSUPPORTED_SIGNATURE_VERSION = 'UNSUPPORTED_SIGNATURE_VERSION';
    public const INVALID_SIGNATURE = 'INVALID_SIGNATURE';

    private const MESSAGES = [
        self::MISSING_HEADERS => 'missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature',
        self::TIMESTAMP_INVALID => 'x-webhook-timestamp is not an ISO 8601 date',
        self::TIMESTAMP_OUT_OF_TOLERANCE => 'delivery is outside the time tolerance (possible replay)',
        self::UNKNOWN_KEY_ID => 'no public key for this x-webhook-key-id',
        self::UNSUPPORTED_SIGNATURE_VERSION => 'unsupported signature version (expected v1=)',
        self::INVALID_SIGNATURE => 'invalid signature',
    ];

    /**
     * @param array<string,string> $publicKeys keyId => PEM. Keep a retired key here
     *                                         while deliveries signed with it may still arrive.
     * @param int                  $tolerance  seconds; 0 disables the check (not recommended)
     */
    public function __construct(
        private readonly array $publicKeys,
        private readonly int $tolerance = 300,
        /** Reference clock, for tests. */
        private readonly ?\DateTimeImmutable $now = null,
    ) {
    }

    /**
     * Verifies a delivery and returns the parsed event.
     *
     * Pass the RAW body — the bytes as they arrived. Decoding and re-encoding the
     * JSON changes them, and the signature will not match.
     *
     * @param array<string,string|array<string>> $headers
     * @return array<string,mixed>
     *
     * @throws WebhookVerificationException answer 400 and do not process the body
     */
    public function verify(array $headers, string $rawBody): array
    {
        $id = $this->header($headers, 'x-webhook-id');
        $timestamp = $this->header($headers, 'x-webhook-timestamp');
        $keyId = $this->header($headers, 'x-webhook-key-id');
        $signature = $this->header($headers, 'x-webhook-signature');

        if ($id === null || $timestamp === null || $keyId === null || $signature === null) {
            $this->fail(self::MISSING_HEADERS);
        }

        $sentAt = strtotime($timestamp);
        if ($sentAt === false) {
            $this->fail(self::TIMESTAMP_INVALID);
        }
        if ($this->tolerance > 0) {
            $now = ($this->now ?? new \DateTimeImmutable())->getTimestamp();
            if (abs($now - $sentAt) > $this->tolerance) {
                $this->fail(self::TIMESTAMP_OUT_OF_TOLERANCE);
            }
        }
        if (!str_starts_with($signature, 'v1=')) {
            $this->fail(self::UNSUPPORTED_SIGNATURE_VERSION);
        }
        $pem = $this->publicKeys[$keyId] ?? null;
        if ($pem === null) {
            $this->fail(self::UNKNOWN_KEY_ID);
        }
        $raw = base64_decode(substr($signature, 3), true);
        if ($raw === false) {
            $this->fail(self::INVALID_SIGNATURE);
        }
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            $this->fail(self::UNKNOWN_KEY_ID);
        }
        if (openssl_verify("{$id}\n{$timestamp}\n{$rawBody}", $raw, $key, OPENSSL_ALGO_SHA256) !== 1) {
            $this->fail(self::INVALID_SIGNATURE);
        }

        $event = json_decode($rawBody, true);
        if (!is_array($event)) {
            $this->fail(self::INVALID_SIGNATURE, 'the signed body is not valid JSON');
        }

        return $event;
    }

    /** @param array<string,string|array<string>> $headers */
    private function header(array $headers, string $name): ?string
    {
        foreach ($headers as $key => $value) {
            // PHP hands headers over in every shape there is: HTTP_X_WEBHOOK_ID from
            // $_SERVER, x-webhook-id from a framework, arrays from others.
            $normalized = strtolower(str_replace('_', '-', (string) $key));
            $normalized = str_starts_with($normalized, 'http-') ? substr($normalized, 5) : $normalized;
            if ($normalized === $name) {
                $found = is_array($value) ? ($value[0] ?? null) : $value;

                return $found === null || $found === '' ? null : (string) $found;
            }
        }

        return null;
    }

    private function fail(string $failure, ?string $message = null): never
    {
        throw new WebhookVerificationException($failure, $message ?? self::MESSAGES[$failure]);
    }
}
