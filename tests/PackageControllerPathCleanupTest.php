<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\PackageController;

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-controller-cleanup-' . bin2hex(random_bytes(8));
$owned = $base . DIRECTORY_SEPARATOR . 'owned';
$outside = $base . DIRECTORY_SEPARATOR . 'outside';
if (!mkdir($owned, 0700, true) || !mkdir($outside, 0700, true)) {
    throw new RuntimeException('Unable to create controller cleanup fixture.');
}

try {
    $controller = (new ReflectionClass(PackageController::class))->newInstanceWithoutConstructor();
    $remove = (new ReflectionClass(PackageController::class))->getMethod('removePath');

    $nested = $owned . DIRECTORY_SEPARATOR . 'nested';
    if (!mkdir($nested, 0700, true)
        || file_put_contents($nested . DIRECTORY_SEPARATOR . 'payload.txt', 'remove me') === false) {
        throw new RuntimeException('Unable to create nested cleanup fixture.');
    }
    $outsideFile = $outside . DIRECTORY_SEPARATOR . 'keep.txt';
    file_put_contents($outsideFile, 'preserve external data');

    $nestedLink = $nested . DIRECTORY_SEPARATOR . 'outside-link';
    if (@symlink($outside, $nestedLink)) {
        $remove->invoke($controller, $owned);
        if (file_exists($owned) || is_link($owned)) {
            throw new RuntimeException('Owned cleanup left the root directory behind.');
        }
        if (!is_file($outsideFile) || file_get_contents($outsideFile) !== 'preserve external data') {
            throw new RuntimeException('Owned cleanup followed a nested symlink.');
        }
    } else {
        $remove->invoke($controller, $owned);
        if (file_exists($owned) || is_link($owned)) {
            throw new RuntimeException('Owned cleanup failed without symlink support.');
        }
    }

    $externalLink = $base . DIRECTORY_SEPARATOR . 'external-root-link';
    if (@symlink($outside, $externalLink)) {
        $remove->invoke($controller, $externalLink);
        if (is_link($externalLink) || !is_file($outsideFile)) {
            throw new RuntimeException('Cleanup followed a symlink supplied as its root.');
        }
    }

    // Absence is idempotent; no failure is needed when the previously owned path is gone.
    $remove->invoke($controller, $owned);

    echo "Controller path cleanup tests passed.\n";
} finally {
    foreach ([$owned, $outside, $base] as $path) {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
        } elseif (is_dir($path)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                if ($item->isLink() || !$item->isDir()) @unlink($item->getPathname());
                else @rmdir($item->getPathname());
            }
            @rmdir($path);
        }
    }
}
