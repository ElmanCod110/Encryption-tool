<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

/** An authenticated package key or payload could not be accepted. */
final class V14AuthenticationException extends RuntimeException
{
}
