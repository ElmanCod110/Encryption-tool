<?php
declare(strict_types=1);

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
