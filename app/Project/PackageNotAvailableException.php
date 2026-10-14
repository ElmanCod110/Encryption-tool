<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/**
 * A package is missing, expired, revoked, or not visible to this owner.
 * The same public classification prevents package-existence enumeration.
 */
final class PackageNotAvailableException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Package is not available.');
    }
}
