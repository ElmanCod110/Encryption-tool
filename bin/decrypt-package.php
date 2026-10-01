#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Security\Validator;

if ($argc < 4 || $argc > 5) {
    fwrite(STDERR, "Usage: php decrypt-package.php <package-dir-or-spkg14> <output-dir> <password> [recovery-key]\n");
    exit(1);
}

[, $package, $output, $password] = array_pad($argv, 4, '');
$recoveryKey = $argv[4] ?? '';
$pattern = getenv('SPK_PATTERN') ?: '';
$temp = null;
try {
    if ($recoveryKey !== '') {
        $recoveryKey = strtoupper(trim($recoveryKey));
        if (!preg_match('/^[0-9A-F]{64}$/', $recoveryKey)) throw new RuntimeException('Invalid recovery key.');
    } else {
        Validator::validatePassword($password);
        Validator::validatePattern($pattern);
    }
    if (is_file($package) && preg_match('/\.spkg14$/i', $package)) {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secure-package-v14-' . bin2hex(random_bytes(12));
        (new PackageArchive())->extract($package, $temp);
        $package = $temp;
    }
    (new V14PackageReader())->restore($package, $output, $password, $pattern, $recoveryKey !== '' ? $recoveryKey : null);
    echo "V14 package restored successfully.\n";
} catch (Throwable) {
    fwrite(STDERR, "Unable to open V14 package.\n");
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
