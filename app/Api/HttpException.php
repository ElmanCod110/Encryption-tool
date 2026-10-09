<?php
declare(strict_types=1);

namespace SecurePackage\Api;

use RuntimeException;

/**
 * An expected HTTP failure with a deliberately safe public message.
 *
 * Internal exception details must never be copied into the response body.
 */
final class HttpException extends RuntimeException
{
    public function __construct(
        public readonly int $statusCode,
        public readonly string $publicMessage,
        ?\Throwable $previous = null
    ) {
        if ($statusCode < 400 || $statusCode > 599) {
            throw new RuntimeException('HTTP exception status must be an error status.');
        }

        parent::__construct('Expected HTTP request failure.', 0, $previous);
    }
}
