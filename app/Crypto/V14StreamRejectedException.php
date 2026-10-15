<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

/** An encrypted file stream is malformed, truncated, or fails authentication. */
final class V14StreamRejectedException extends RuntimeException
{
}
