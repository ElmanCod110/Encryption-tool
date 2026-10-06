<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\ReplayGuard;

$dir = sys_get_temp_dir() . '/sp-v12-replay-' . bin2hex(random_bytes(5));
$guard = new ReplayGuard($dir);
$id = 'one-time-' . bin2hex(random_bytes(12));
if (!$guard->consume($id, 60)) throw new RuntimeException('First replay consume failed.');
if ($guard->consume($id, 60)) throw new RuntimeException('Replay was not rejected.');
foreach (glob($dir . '/*') ?: [] as $file) @unlink($file);
@rmdir($dir);
echo "Replay guard tests passed.\n";
