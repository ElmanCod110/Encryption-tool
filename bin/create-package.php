#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
require __DIR__ . '/ConsoleSecretPrompt.php';

use SecurePackage\Project\StablePackageWriter;

$arguments = array_slice($argv, 1);
$noRecovery = in_array('--no-recovery', $arguments, true);
$arguments = array_values(array_filter($arguments, static fn(string $arg): bool => $arg !== '--no-recovery'));
if (count($arguments) !== 2 || in_array('--help', $arguments, true)) {
    fwrite(STDERR, "Usage: php bin/create-package.php <source-directory> <destination.spkg> [--no-recovery]\n");
    fwrite(STDERR, "Credentials are prompted without echo. For automation, use SPK_PASSWORD and SPK_PATTERN environment variables.\n");
    exit(1);
}

[$sourceDirectory, $destination] = $arguments;
$password = '';
$pattern = '';
try {
    if (strtolower(pathinfo($destination, PATHINFO_EXTENSION)) !== 'spkg') {
        throw new RuntimeException('The output filename must end in .spkg.');
    }
    $password = ConsoleSecretPrompt::read('Package password', 'SPK_PASSWORD');
    $pattern = ConsoleSecretPrompt::read('Pattern credential', 'SPK_PATTERN');
    $result = (new StablePackageWriter())->build(
        $sourceDirectory, $destination, $password, $pattern, null, !$noRecovery
    );
    echo "SPKG package created successfully.\n";
    echo 'File: ' . $destination . "\n";
    echo 'Files: ' . (int) ($result['files'] ?? 0) . "\n";
    echo 'Directories: ' . (int) ($result['directories'] ?? 0) . "\n";
    echo 'Plaintext bytes: ' . (int) ($result['total_plain_bytes'] ?? 0) . "\n";
    if (isset($result['recovery_key']) && is_string($result['recovery_key'])) {
        fwrite(STDOUT, "\nRecovery key — shown once; store it offline:\n" . $result['recovery_key'] . "\n\n");
    }
} catch (Throwable $error) {
    fwrite(STDERR, 'Unable to create SPKG package: ' . $error->getMessage() . "\n");
    exit(2);
} finally {
    if ($password !== '') sodium_memzero($password);
    if ($pattern !== '') sodium_memzero($pattern);
}
