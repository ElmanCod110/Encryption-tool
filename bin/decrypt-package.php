#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\StablePackageDescriptor;
use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Security\Validator;

if ($argc < 4 || $argc > 5) {
    fwrite(STDERR, "Usage: php decrypt-package.php <package-file-or-legacy-dir-or-spkg14> <output-dir> <password> [recovery-key]\n");
    fwrite(STDERR, "Stable .spkg recovery keys use canonical base64url; legacy V14 recovery keys use 64 hexadecimal characters.\n");
    exit(1);
}

[, $package, $output, $password] = array_pad($argv, 4, '');
$recoveryKey = $argv[4] ?? '';
$pattern = getenv('SPK_PATTERN') ?: '';
$temp = null;
$format = null;

try {
    if (is_link($package)) {
        throw new RuntimeException('Package path must not be a symbolic link.');
    }

    if (is_file($package)) {
        $handle = @fopen($package, 'rb');
        if ($handle === false) throw new RuntimeException('Unable to inspect package file.');
        try {
            $prefix = fread($handle, StablePackageDescriptor::MAGIC_BYTES);
            if (!is_string($prefix)) throw new RuntimeException('Unable to inspect package file.');
        } finally {
            fclose($handle);
        }

        if (strlen($prefix) === StablePackageDescriptor::MAGIC_BYTES
            && hash_equals(StablePackageDescriptor::MAGIC, $prefix)) {
            $format = 'STABLE-BINARY';
        } elseif (str_starts_with($prefix, "PK")) {
            $format = 'SECURE-PKG-V14';
            $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secure-package-v14-' . bin2hex(random_bytes(12));
            (new PackageArchive())->extract($package, $temp);
            $package = $temp;
        } else {
            throw new RuntimeException('Unrecognized package format.');
        }
    } elseif (is_dir($package)) {
        $format = 'SECURE-PKG-V14';
    } else {
        throw new RuntimeException('Package path is unavailable.');
    }

    if ($format === 'STABLE-BINARY') {
        if ($recoveryKey === '') {
            Validator::validatePassword($password);
            Validator::validatePattern($pattern);
        }
        (new StablePackageReader())->restore($package, $output, $password, $pattern, $recoveryKey !== '' ? $recoveryKey : null);
        echo "Stable binary package restored successfully.\n";
    } else {
        if ($recoveryKey !== '') {
            $recoveryKey = strtoupper(trim($recoveryKey));
            if (!preg_match('/^[0-9A-F]{64}$/', $recoveryKey)) throw new RuntimeException('Invalid legacy recovery key.');
        } else {
            Validator::validatePassword($password);
            Validator::validatePattern($pattern);
        }
        (new V14PackageReader())->restore($package, $output, $password, $pattern, $recoveryKey !== '' ? $recoveryKey : null);
        echo "Legacy V14 package restored successfully.\n";
    }
} catch (Throwable) {
    fwrite(STDERR, "Unable to open package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
    sodium_memzero($recoveryKey);
    if ($temp !== null && is_dir($temp)) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($temp);
    }
}
