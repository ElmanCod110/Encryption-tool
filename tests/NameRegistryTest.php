<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\FileProjectNameRegistry;

$file = sys_get_temp_dir() . '/securepkg-name-registry-' . bin2hex(random_bytes(6)) . '.db';
$registry = new FileProjectNameRegistry($file, 'test-server-pepper');
$registry->reserve('My Project');
try {
    $registry->reserve('my project');
    throw new RuntimeException('Case-insensitive duplicate name was accepted.');
} catch (Throwable) {
}
$registry->reserve('پروژه من');
try {
    $registry->reserve('پروژه من');
    throw new RuntimeException('Unicode duplicate name was accepted.');
} catch (Throwable) {
}
@unlink($file);
echo "Project name registry tests passed.\n";
