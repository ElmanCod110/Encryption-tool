<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/** Credentials or authenticated package contents were rejected. */
final class PackageRestoreRejectedException extends RuntimeException
{
}
