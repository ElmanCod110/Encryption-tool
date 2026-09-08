#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Project\PackageReader;
use TCH\Security\Validator;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php decrypt-package.php <package-dir> <output-dir> <password>\n");
    exit(1);
}

[$script, $package, $output, $password] = $argv;
$pattern = getenv('TCH_PATTERN') ?: '';
try {
    Validator::validatePassword($password);
    Validator::validatePattern($pattern);
    (new PackageReader())->restore($package, $output, $password, $pattern);
    echo "Package restored successfully.\n";
} catch (Throwable $e) {
    fwrite(STDERR, "Unable to open package.\n");
    exit(2);
}
