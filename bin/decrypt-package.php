#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
require __DIR__ . '/ConsoleSecretPrompt.php';

use SecurePackage\Project\StablePackageReader;

$arguments = array_slice($argv, 1);
$useRecovery = in_array('--recovery', $arguments, true);
$arguments = array_values(array_filter($arguments, static fn(string $arg): bool => $arg !== '--recovery'));
if (count($arguments) !== 2 || in_array('--help', $arguments, true)) {
    fwrite(STDERR, "Usage: php bin/decrypt-package.php <package.spkg> <output-directory> [--recovery]\n");
    fwrite(STDERR, "Credentials are prompted without echo. For automation, use SPK_PASSWORD/SPK_PATTERN or SPK_RECOVERY_KEY.\n");
    exit(1);
}

[$package, $output] = $arguments;
$password = '';
$pattern = '';
$recoveryKey = '';
try {
    if (strtolower(pathinfo($package, PATHINFO_EXTENSION)) !== 'spkg' || is_link($package) || !is_file($package)) {
        throw new RuntimeException('Only a regular SPKG binary package file is supported.');
    }
    if ($useRecovery) {
        $recoveryKey = ConsoleSecretPrompt::read('Recovery key', 'SPK_RECOVERY_KEY');
    } else {
        $password = ConsoleSecretPrompt::read('Package password', 'SPK_PASSWORD');
        $pattern = ConsoleSecretPrompt::read('Pattern credential', 'SPK_PATTERN');
    }
    $result = (new StablePackageReader())->restore(
        $package, $output, $password, $pattern, $recoveryKey !== '' ? $recoveryKey : null
    );
    echo "SPKG package restored successfully.\n";
    echo 'Files: ' . (int) ($result['files'] ?? 0) . "\n";
    echo 'Directories: ' . (int) ($result['directories'] ?? 0) . "\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'Unable to open SPKG package: ' . $error->getMessage() . "\n");
    exit(2);
} finally {
    if ($password !== '') sodium_memzero($password);
    if ($pattern !== '') sodium_memzero($pattern);
    if ($recoveryKey !== '') sodium_memzero($recoveryKey);
}
