<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/**
 * Binds sensitive browser sessions to a rotating random device identifier.
 */
final class DeviceBinding
{
    public static function ensure(): string
    {
        WebSecurity::startSession();
        if (!isset($_SESSION['device_id']) || !is_string($_SESSION['device_id']) || !preg_match('/^[a-f0-9]{64}$/', $_SESSION['device_id'])) {
            $_SESSION['device_id'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['device_id'];
    }

    public static function rotate(): string
    {
        WebSecurity::startSession();
        $_SESSION['device_id'] = bin2hex(random_bytes(32));
        return $_SESSION['device_id'];
    }

    public static function fingerprint(): string
    {
        return hash('sha256', self::ensure());
    }

    public static function assert(string $fingerprint): void
    {
        if (!hash_equals($fingerprint, self::fingerprint())) {
            throw new RuntimeException('Session binding failed.');
        }
    }
}
