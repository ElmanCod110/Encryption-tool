<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/** The requested archive step is not valid for the job's current state. */
final class ArchiveStepConflictException extends RuntimeException
{
}
