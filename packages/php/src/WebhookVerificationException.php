<?php

declare(strict_types=1);

namespace Catalisa\Biometrics;

use RuntimeException;

/** A delivery that failed verification. Answer 400 and do not process the body. */
final class WebhookVerificationException extends RuntimeException
{
    public function __construct(
        /** Which check failed: MISSING_HEADERS, INVALID_SIGNATURE, TIMESTAMP_OUT_OF_TOLERANCE… */
        public readonly string $failure,
        string $message,
    ) {
        parent::__construct($message);
    }
}
