<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/**
 * A local storage/runtime operation failed while creating, reading, restoring, or cleaning package artifacts.
 */
final class PackageStorageException extends RuntimeException
{
}
