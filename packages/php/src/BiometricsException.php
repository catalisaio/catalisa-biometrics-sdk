<?php

declare(strict_types=1);

namespace Catalisa\Biometrics;

use RuntimeException;

/**
 * Every failed call throws this. The API answers
 * `{"error":"<code>","message":"...","details":{...}}`, so $code is the API's
 * own word for what happened — branch on it, never on the message.
 */
class BiometricsException extends RuntimeException
{
    public function __construct(
        /** HTTP status, or 0 when the request never reached the API. */
        public readonly int $status,
        /** API error code (VALIDATION, NOT_FOUND, QUOTA_EXCEEDED…), or TIMEOUT/CONNECTION. */
        public readonly string $errorCode,
        string $message,
        /** Whatever the API attached: the offending fields, the quota numbers. */
        public readonly array $details = [],
        /** `x-request-id`, when the API sends one — quote it in a support ticket. */
        public readonly ?string $requestId = null,
        /** `Retry-After` in seconds, on a 429. */
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct($message, $status);
    }

    /** The customer's monthly allowance is gone. A test key never gets here. */
    public function isQuotaExceeded(): bool
    {
        return $this->errorCode === 'QUOTA_EXCEEDED';
    }

    /** The subaccount is suspended: nothing opens until it is reactivated. */
    public function isSubaccountSuspended(): bool
    {
        return $this->errorCode === 'SUBACCOUNT_SUSPENDED';
    }

    /** Worth trying again by itself (rate limit, server fault, network). */
    public function isTransient(): bool
    {
        return $this->status === 429 || $this->status >= 500 || $this->status === 0;
    }

    /**
     * Builds the exception from what the API answered. A body that is not the
     * expected envelope — an HTML page from a proxy, say — still yields a usable
     * code, taken from the status.
     */
    public static function fromResponse(int $status, mixed $body, array $headers): self
    {
        $code = self::codeForStatus($status);
        $message = '';
        $details = [];

        if (is_array($body)) {
            if (is_string($body['error'] ?? null) && $body['error'] !== '') {
                $code = $body['error'];
            }
            if (is_string($body['message'] ?? null)) {
                $message = $body['message'];
            }
            if (is_array($body['details'] ?? null)) {
                $details = $body['details'];
                // The machine-readable code lives inside details on the cases that
                // carry numbers with them (quota, suspension).
                if (is_string($details['code'] ?? null) && $details['code'] !== '') {
                    $code = $details['code'];
                }
            }
        }
        if ($message === '') {
            $message = self::messageForStatus($status);
        }

        $retryAfter = isset($headers['retry-after']) ? (int) $headers['retry-after'] : null;

        return new self($status, $code, $message, $details, $headers['x-request-id'] ?? null, $retryAfter);
    }

    private static function codeForStatus(int $status): string
    {
        return match (true) {
            $status === 400 => 'VALIDATION',
            $status === 401 => 'UNAUTHORIZED',
            $status === 402 => 'QUOTA_EXCEEDED',
            $status === 403 => 'FORBIDDEN',
            $status === 404 => 'NOT_FOUND',
            $status === 409 => 'CONFLICT',
            $status === 413 => 'PAYLOAD_TOO_LARGE',
            $status === 415 => 'VALIDATION',
            $status === 429 => 'RATE_LIMITED',
            $status >= 500 => 'INTERNAL',
            default => 'ERROR',
        };
    }

    private static function messageForStatus(int $status): string
    {
        return match (true) {
            $status === 401 => 'API key missing, wrong or revoked',
            $status === 402 => 'monthly allowance exhausted',
            $status === 403 => 'this key may not do that',
            $status === 404 => 'not found in this scope',
            $status === 429 => 'too many requests',
            $status >= 500 => 'the API failed',
            default => "request failed with status {$status}",
        };
    }
}
