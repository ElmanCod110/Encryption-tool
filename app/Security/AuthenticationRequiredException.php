<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/** Signals that an authenticated session is required without exposing account details. */
final class AuthenticationRequiredException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Authentication is required.');
    }
}
