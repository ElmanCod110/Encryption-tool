<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/**
 * A local storage/runtime operation failed while reading or restoring a package.
 */
final class PackageStorageException extends RuntimeException
{
}
