<?php
declare(strict_types=1);

namespace SecurePackage\Client;

use RuntimeException;

/**
 * Lightweight content-defined chunking helper for server-side tooling and tests.
 * The browser implementation mirrors the boundary function in V10 client code.
 */
final class ContentDefinedChunker
{
    public const MIN = 1024 * 1024;
    public const TARGET = 4 * 1024 * 1024;
    public const MAX = 8 * 1024 * 1024;

    public static function split(string $data): array
    {
        if ($data === '') {
            return [''];
        }
        $chunks = [];
        $start = 0;
        $window = 48;
        $mask = self::TARGET - 1;
        $rolling = 0;
        $length = strlen($data);
        for ($i = 0; $i < $length; $i++) {
            $rolling = (($rolling << 5) ^ ord($data[$i])) & 0xFFFFFFFF;
            $size = $i - $start + 1;
            if (($size >= self::MIN && (($rolling & $mask) === 0 || $size >= self::MAX)) && $size >= $window) {
                $chunks[] = substr($data, $start, $size);
                $start = $i + 1;
                $rolling = 0;
            }
        }
        if ($start < $length) {
            $chunks[] = substr($data, $start);
        }
        return $chunks;
    }
}
