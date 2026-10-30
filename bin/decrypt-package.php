#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageReader;

if ($argc < 5 || $argc > 6) {
    fwrite(STDERR, "Usage: php decrypt-package.php <package.spkg> <output-dir> <password> <pattern> [recovery-key]\n");
    exit(1);
}
[, $package, $output, $password, $pattern] = array_pad($argv, 5, '');
$recoveryKey = $argv[5] ?? '';
try {
    if (strtolower(pathinfo($package, PATHINFO_EXTENSION)) !== 'spkg') {
        throw new RuntimeException('Only SPKG packages are supported by this application.');
    }
    (new StablePackageReader())->restore(
        $package, $output, $password, $pattern,
        $recoveryKey !== '' ? $recoveryKey : null
    );
    echo "SPKG package restored successfully.\n";
} catch (Throwable) {
    fwrite(STDERR, "Unable to open SPKG package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
    sodium_memzero($recoveryKey);
}
