<?php
declare(strict_types=1);

$versionFile = __DIR__ . '/VERSION';
$version = is_file($versionFile) ? trim((string) file_get_contents($versionFile)) : '';
if (!preg_match('/^\d+\.\d+\.\d+$/', $version)) {
    throw new RuntimeException('Invalid Secure Package version metadata.');
}
define('SECURE_PACKAGE_VERSION', $version);
define('SECURE_PACKAGE_MAJOR_VERSION', (int) explode('.', $version)[0]);

spl_autoload_register(static function (string $class): void {
    $prefix = 'SecurePackage\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/app/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
