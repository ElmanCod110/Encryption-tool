#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageWriter;
use SecurePackage\Security\Validator;

if ($argc !== 5) {
    fwrite(STDERR, "Usage: php encrypt-directory.php <source-dir> <output-file.spkg> <password> <pattern>\n");
    exit(1);
}
[, $source, $output, $password, $pattern] = $argv;
try {
    Validator::validatePassword($password);
    Validator::validatePattern($pattern);
    if (!is_dir($source) || is_link($source)) throw new RuntimeException('Source directory is unavailable.');
    if (strtolower(pathinfo($output, PATHINFO_EXTENSION)) !== 'spkg') throw new RuntimeException('Output filename must use the .spkg extension.');
    $result = (new StablePackageWriter())->build($source, $output, $password, $pattern, null, true);
    echo "Package created: {$output}\n";
    echo "Format: SPKG\n";
    echo "Package ID: {$result['package_id']}\n";
    echo "Files: {$result['files']}\n";
    echo "Plaintext bytes: {$result['total_plain_bytes']}\n";
    if (is_string($result['recovery_key'] ?? null)) {
        echo "Recovery key (store offline): {$result['recovery_key']}\n";
    }
} catch (Throwable) {
    fwrite(STDERR, "Unable to create SPKG package.\n");
    exit(2);
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
}
