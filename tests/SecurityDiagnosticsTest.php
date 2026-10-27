<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\SecurityDiagnostics;

$diagnostics = SecurityDiagnostics::run(dirname(__DIR__));

if (($diagnostics['version'] ?? null) !== SECURE_PACKAGE_MAJOR_VERSION) {
    throw new RuntimeException('Diagnostics application major version mismatch.');
}
if (($diagnostics['version_string'] ?? null) !== SECURE_PACKAGE_VERSION) {
    throw new RuntimeException('Diagnostics application version string mismatch.');
}
if (($diagnostics['server_package_format'] ?? null) !== 'SECURE-PKG-V14'
    || ($diagnostics['server_package_format_version'] ?? null) !== 14) {
    throw new RuntimeException('Server package format metadata mismatch.');
}
if (($diagnostics['author'] ?? '') !== 'ElmanCod110') {
    throw new RuntimeException('Author mismatch.');
}
if (($diagnostics['checks']['php_version'] ?? false) !== true) {
    throw new RuntimeException('PHP runtime is too old.');
}
if (($diagnostics['checks']['zip'] ?? false) !== true && getenv('SPK_ALLOW_ZIPLESS_DIAGNOSTICS') !== '1') {
    throw new RuntimeException('ZIP extension is required for server package diagnostics.');
}
if (($diagnostics['checks']['sodium'] ?? false) !== true) {
    throw new RuntimeException('Sodium is required.');
}

echo "Security diagnostics tests passed.\n";
