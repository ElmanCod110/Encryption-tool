<?php
declare(strict_types=1);

namespace SecurePackage\Security;

final class SecurityPolicy
{
    public static function publicFailure(): string
    {
        return 'Unable to complete the requested operation.';
    }

    public static function credentialFailure(): string
    {
        return 'Unable to open package.';
    }
}
