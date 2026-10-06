<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class RecoveryKey
{
    public static function generate(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function validate(string $value): void
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $value)) {
            throw new RuntimeException('Invalid recovery key.');
        }
    }
}
