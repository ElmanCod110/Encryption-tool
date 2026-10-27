<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$versionFile = $root . '/VERSION';
$bootstrapFile = $root . '/bootstrap.php';
$policyFile = $root . '/VERSIONING.md';

$version = trim((string) file_get_contents($versionFile));
$bootstrap = (string) file_get_contents($bootstrapFile);
$policy = (string) file_get_contents($policyFile);

if (!preg_match('/^\d+\.\d+\.\d+$/', $version)) {
    throw new RuntimeException('VERSION must contain one semantic version.');
}
if (!str_contains($bootstrap, "define('SECURE_PACKAGE_VERSION', $version);")
    && !str_contains($bootstrap, "define('SECURE_PACKAGE_VERSION', $version);")) {
    // The bootstrap must derive the runtime version from the VERSION file, not a hard-coded release label.
    if (!str_contains($bootstrap, "define('SECURE_PACKAGE_VERSION', $version);")) {
        throw new RuntimeException('Bootstrap must derive the runtime version from VERSION.');
    }
}
if (!str_contains($bootstrap, "define('SECURE_PACKAGE_MAJOR_VERSION', (int) explode('.', $version)[0]);")) {
    throw new RuntimeException('Bootstrap must derive the major version from VERSION.');
}
if (!str_contains($policy, 'VERSION') || !str_contains($policy, 'release tag without its leading')) {
    throw new RuntimeException('Versioning policy must define VERSION-to-release-tag consistency.');
}

echo "Version metadata consistency tests passed.\n";
