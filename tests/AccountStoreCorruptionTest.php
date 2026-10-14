<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\AccountStore;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-account-store-' . bin2hex(random_bytes(8));
$directory = $root . DIRECTORY_SEPARATOR . 'accounts';
if (!mkdir($directory, 0700, true)) {
    throw new RuntimeException('Unable to create account-store test directory.');
}
$file = $directory . DIRECTORY_SEPARATOR . 'users.json';
$corrupt = "{not-valid-json";
file_put_contents($file, $corrupt);
chmod($file, 0600);

try {
    $store = new AccountStore($file);
    $rejected = false;
    try {
        $store->register('test.user', 'Cobalt!River72_Moon');
    } catch (RuntimeException) {
        $rejected = true;
    }

    if (!$rejected) {
        throw new RuntimeException('Account store accepted corrupted JSON.');
    }
    if (file_get_contents($file) !== $corrupt) {
        throw new RuntimeException('Account registration overwrote corrupted account data.');
    }

    echo "Account store corruption regression tests passed.\n";
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $path) {
        if (is_link($path) || is_file($path)) @unlink($path);
    }
    @rmdir($directory);
    @rmdir($root);
}
