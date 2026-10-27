<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageService;
use SecurePackage\Storage\FileStore;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-v14-service-cleanup-' . bin2hex(random_bytes(8));
$storage = $root . DIRECTORY_SEPARATOR . 'storage';
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create V14 service cleanup fixture.');
}

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
        $removeTree($entry->getPathname());
    }
    @rmdir($path);
};

$password = 'Strong!Password2026#';
$pattern = 'Az!71_xYp#42Qw9';

try {
    $service = new V14PackageService(new V14PackageBuilder(), new FileStore($storage));
    $failedAsExpected = false;
    try {
        $service->build(
            $root . DIRECTORY_SEPARATOR . 'source-does-not-exist',
            'cleanup-test',
            $password,
            $pattern,
            false
        );
    } catch (RuntimeException) {
        $failedAsExpected = true;
    }

    if (!$failedAsExpected) {
        throw new RuntimeException('A V14 build with a missing source directory was accepted.');
    }
    $remaining = iterator_to_array(new FilesystemIterator($storage, FilesystemIterator::SKIP_DOTS));
    if ($remaining !== []) {
        throw new RuntimeException('Failed V14 package build left artifacts in storage.');
    }

    echo "V14 package service cleanup regression test passed.\n";
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
    $removeTree($root);
}
