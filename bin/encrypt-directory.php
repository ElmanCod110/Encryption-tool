#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Crypto\KeyDerivation;
use TCH\Project\PackageBuilder;
use TCH\Project\PackageId;
use TCH\Security\Validator;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php encrypt-directory.php <source-dir> <output-dir> <password>\n");
    exit(1);
}

[$script, $source, $output, $password] = $argv;
$pattern = getenv('TCH_PATTERN') ?: '';
if ($pattern === '') {
    fwrite(STDERR, "TCH_PATTERN environment variable is required.\n");
    exit(1);
}
Validator::validatePassword($password);
Validator::validatePattern($pattern);
if (!is_dir($source)) {
    fwrite(STDERR, "Source directory does not exist.\n");
    exit(1);
}

$packageId = PackageId::generate();
$packageDir = rtrim($output, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $packageId;
mkdir($packageDir . DIRECTORY_SEPARATOR . 'blobs', 0700, true);
(new PackageBuilder())->build($source, $packageDir, $password, $pattern);
echo "Package created: {$packageDir}\n";
