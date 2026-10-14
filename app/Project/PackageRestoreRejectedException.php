<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/**
 * The package, credentials, or authenticated contents were rejected.
 * The message is internal-only; API responses must use a generic public message.
 */
final class PackageRestoreRejectedException extends RuntimeException
{
}
