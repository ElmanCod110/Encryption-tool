<?php
declare(strict_types=1);

namespace TCH\Project;

final class PackageId
{
    public static function generate(): string
    {
        return bin2hex(random_bytes(18));
    }
}
