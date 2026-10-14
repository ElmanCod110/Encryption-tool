<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class UploadException extends RuntimeException
{
    public function __construct(
        public readonly int $statusCode,
        public readonly string $publicMessage
    ) {
        parent::__construct($publicMessage);
    }
}
