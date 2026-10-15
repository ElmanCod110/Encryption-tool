<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/**
 * The archive step conflicts with the current job state.
 */
final class ArchiveStepConflictException extends RuntimeException
{
}
