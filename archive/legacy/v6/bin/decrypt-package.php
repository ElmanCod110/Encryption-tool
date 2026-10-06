#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\PackageReader;
use SecurePackage\Security\Validator;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php decrypt-package.php <package-dir-or-spkg> <output-dir> <password>\n");
    exit(1);
}

[, $package, $output, $password] = $argv;
$pattern = getenv('SPK_PATTERN') ?: '';
$temp = null;
try {
    Validator::validatePassword($password);
    Validator::validatePattern($pattern);
    if (is_file($package) && preg_match('/\.spkg$/i', $package)) {
        $temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secure-package-' . bin2hex(random_bytes(12));
        (new PackageArchive())->extract($package, $temp);
        $package = $temp;
    }
    (new PackageReader())->restore($package, $output, $password, $pattern);
    echo "Package restored successfully.\n";
} catch (Throwable) {
    fwrite(STDERR, "Unable to open package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
    if ($temp !== null) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($temp);
    }
}
