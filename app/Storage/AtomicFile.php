<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class AtomicFile
{
    public static function write(string $path, string $contents, int $mode = 0600): void
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize storage directory.');
        }
        $temp = $path . '.partial.' . bin2hex(random_bytes(8));
        if (file_put_contents($temp, $contents, LOCK_EX) === false) {
            @unlink($temp);
            throw new RuntimeException('Unable to write storage file.');
        }
        @chmod($temp, $mode);
        if (!rename($temp, $path)) {
            @unlink($temp);
            throw new RuntimeException('Unable to finalize storage file.');
        }
        @chmod($path, $mode);
    }
}
