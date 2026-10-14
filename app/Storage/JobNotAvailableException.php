<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

/**
 * Represents a job that is absent or not visible to the current owner.
 */
final class JobNotAvailableException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Job does not exist.');
    }
}
