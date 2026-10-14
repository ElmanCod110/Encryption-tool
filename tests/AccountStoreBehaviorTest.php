<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\AccountStore;
use SecurePackage\Security\DuplicateAccountException;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-account-behavior-' . bin2hex(random_bytes(8));
$directory = $root . DIRECTORY_SEPARATOR . 'accounts';
if (!mkdir($directory, 0700, true)) {
    throw new RuntimeException('Unable to create account behavior fixture.');
}
$file = $directory . DIRECTORY_SEPARATOR . 'users.json';

try {
    $store = new AccountStore($file);
    $password = 'Cobalt!River72_Moon';
    $id = $store->register('Valid.User', $password);
    if (!preg_match('/^[a-f0-9]{32}$/', $id) || $store->verify('valid.user', $password) !== $id) {
        throw new RuntimeException('Valid account registration and verification failed.');
    }

    if ($store->verify('invalid username', $password) !== null) {
        throw new RuntimeException('Malformed username was accepted during login verification.');
    }

    $duplicateRejected = false;
    try {
        $store->register('valid.user', $password);
    } catch (DuplicateAccountException) {
        $duplicateRejected = true;
    }
    if (!$duplicateRejected) {
        throw new RuntimeException('Duplicate account registration was not classified.');
    }

    $invalidInputRejected = false;
    try {
        $store->register('bad username', $password);
    } catch (InvalidArgumentException) {
        $invalidInputRejected = true;
    }
    if (!$invalidInputRejected) {
        throw new RuntimeException('Invalid registration input was not classified.');
    }

    echo "Account store behavior tests passed.\n";
} finally {
    if (is_dir($root)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
            else @unlink($item->getPathname());
        }
        @rmdir($root);
    }
}
