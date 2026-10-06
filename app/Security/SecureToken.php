<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class SecureToken
{
    public static function validateHex(string $token, int $bytes): string
    {
        $expected = $bytes * 2;
        if ($bytes < 16 || !preg_match('/^[a-f0-9]{' . $expected . '}$/', $token)) {
            throw new RuntimeException('Invalid token.');
        }
        return $token;
    }
}
