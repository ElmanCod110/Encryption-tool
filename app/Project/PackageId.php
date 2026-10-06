<?php
declare(strict_types=1);

namespace SecurePackage\Project;

final class PackageId
{
    public static function generate(): string
    {
        return bin2hex(random_bytes(24));
    }

    public static function assert(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
            throw new \RuntimeException('Invalid package identifier.');
        }
    }
}
