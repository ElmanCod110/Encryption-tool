#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\PackageId;
use SecurePackage\Security\Validator;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php encrypt-directory.php <source-dir> <output-dir> <password>\n");
    exit(1);
}

[, $source, $output, $password] = $argv;
$pattern = getenv('SPK_PATTERN') ?: '';
if ($pattern === '') { fwrite(STDERR, "SPK_PATTERN environment variable is required.\n"); exit(1); }
try {
    Validator::validatePassword($password);
    Validator::validatePattern($pattern);
    if (!is_dir($source)) throw new RuntimeException('Source directory does not exist.');
    $packageId = PackageId::generate();
    $packageDir = rtrim($output, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $packageId;
    @mkdir($packageDir, 0700, true);
    $result = (new V14PackageBuilder())->build($source, $packageDir, $password, $pattern, $packageId, true);
    echo "Package created: {$packageDir}\n";
    echo "Format: {$result['format']}\n";
    if ($result['recovery_key'] !== null) echo "Recovery key: {$result['recovery_key']}\n";
} catch (Throwable $e) {
    fwrite(STDERR, "Unable to create package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
}
