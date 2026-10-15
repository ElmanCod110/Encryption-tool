<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/**
 * The submitted archive or its requested extraction step is invalid or unsupported.
 * Controllers must map this to a generic 4xx response, never expose the message.
 */
final class ArchiveProcessingException extends RuntimeException
{
}
