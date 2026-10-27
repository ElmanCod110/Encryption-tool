<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/** Missing, expired, revoked, or non-owned packages share one public classification. */
final class PackageNotAvailableException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Package is not available.');
    }
}
