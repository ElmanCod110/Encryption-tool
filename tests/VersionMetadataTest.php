<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$config = require dirname(__DIR__) . '/config/config.php';
$versionFile = trim((string) file_get_contents(dirname(__DIR__) . '/VERSION'));
$expectedMajor = (int) explode('.', $versionFile)[0];

if (!preg_match('/^\d+\.\d+\.\d+$/', $versionFile)) {
    throw new RuntimeException('VERSION must contain one semantic version.');
}
if (SECURE_PACKAGE_VERSION !== $versionFile) {
    throw new RuntimeException('Bootstrap version differs from VERSION.');
}
if (($config['app']['version_string'] ?? null) !== $versionFile) {
    throw new RuntimeException('Displayed application version differs from VERSION.');
}
if (($config['app']['version'] ?? null) !== $expectedMajor) {
    throw new RuntimeException('Application major version differs from VERSION.');
}
if (($config['app']['format'] ?? null) !== 'SECURE-PKG-V14') {
    throw new RuntimeException('Server package-format identifier unexpectedly changed.');
}

$mainPage = (string) file_get_contents(dirname(__DIR__) . '/public/index.php');
if (!str_contains($mainPage, "version_string")) {
    throw new RuntimeException('Main UI does not consume the shared application version.');
}

echo "Version metadata tests passed.\n";
