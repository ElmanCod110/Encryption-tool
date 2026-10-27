<?php
declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/bootstrap.php';

$version = trim((string) file_get_contents($root . '/VERSION'));
$policy = (string) file_get_contents($root . '/VERSIONING.md');

if (!preg_match('/^\d+\.\d+\.\d+$/', $version)) {
    throw new RuntimeException('VERSION must contain one semantic version.');
}
if (SECURE_PACKAGE_VERSION !== $version) {
    throw new RuntimeException('Runtime version must be derived from VERSION.');
}
$expectedMajor = (int) explode('.', $version)[0];
if (SECURE_PACKAGE_MAJOR_VERSION !== $expectedMajor) {
    throw new RuntimeException('Runtime major version must be derived from VERSION.');
}
if (!str_contains($policy, 'release tag without its leading')) {
    throw new RuntimeException('Versioning policy must define VERSION-to-release-tag consistency.');
}

echo "Version metadata consistency tests passed.\n";
