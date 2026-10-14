<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\PackageAccessTokenStore;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-access-token-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) {
    throw new RuntimeException('Unable to create token-store test directory.');
}

try {
    $store = new PackageAccessTokenStore($directory, 60);

    $singleUse = $store->issue('package-single-use', 'account:owner-a', true);
    $first = $store->consume($singleUse);
    if (($first['package_id'] ?? null) !== 'package-single-use') {
        throw new RuntimeException('Single-use token did not return its expected package.');
    }

    $replayRejected = false;
    try {
        $store->consume($singleUse);
    } catch (RuntimeException) {
        $replayRejected = true;
    }
    if (!$replayRejected) {
        throw new RuntimeException('Single-use access token was accepted more than once.');
    }

    $reusable = $store->issue('package-reusable', 'account:owner-b', false);
    if (($store->consume($reusable)['package_id'] ?? null) !== 'package-reusable'
        || ($store->consume($reusable)['package_id'] ?? null) !== 'package-reusable') {
        throw new RuntimeException('Reusable token behavior changed unexpectedly.');
    }

    $invalidRejected = false;
    try {
        $store->consume('../invalid');
    } catch (RuntimeException) {
        $invalidRejected = true;
    }
    if (!$invalidRejected) {
        throw new RuntimeException('Malformed token was accepted.');
    }

    echo "Package access token regression tests passed.\n";
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_link($file) || is_file($file)) @unlink($file);
    }
    @rmdir($directory);
}
