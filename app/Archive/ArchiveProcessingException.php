<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/** Invalid or unsupported archive input; safe to map to a generic 4xx response. */
final class ArchiveProcessingException extends RuntimeException
{
}
