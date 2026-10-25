#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageId;
use SecurePackage\Project\StablePackageWriter;
use SecurePackage\Security\Validator;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php encrypt-directory.php <source-dir> <output-dir> <password>\n");
    fwrite(STDERR, "Set SPK_PATTERN to the independent high-entropy pattern.\n");
    exit(1);
}

[, $source, $output, $password] = $argv;
$pattern = getenv('SPK_PATTERN') ?: '';
try {
    Validator::validatePassword($password);
    Validator::validatePattern($pattern);
    if (!is_dir($source) || is_link($source)) {
        throw new RuntimeException('Source directory does not exist or is unsafe.');
    }
    if (is_link($output)) {
        throw new RuntimeException('Output directory must not be a symbolic link.');
    }
    if (!is_dir($output) && !@mkdir($output, 0700, true) && !is_dir($output)) {
        throw new RuntimeException('Unable to create output directory.');
    }
    $outputRoot = realpath($output);
    if ($outputRoot === false || is_link($outputRoot)) {
        throw new RuntimeException('Unable to validate output directory.');
    }

    $packageId = PackageId::generate();
    $packageFile = rtrim($outputRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $packageId . '.spkg';
    $result = (new StablePackageWriter())->build($source, $packageFile, $password, $pattern, $packageId, true);
    echo "Package created: {$packageFile}\n";
    echo "Format: STABLE-BINARY\n";
    if ($result['recovery_key'] !== null) {
        echo "Recovery key: {$result['recovery_key']}\n";
        echo "Store this recovery key offline. It cannot be recovered from the package.\n";
    }
} catch (Throwable) {
    fwrite(STDERR, "Unable to create package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
}
