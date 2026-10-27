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

    $revoked = $store->issue('package-to-revoke', 'account:owner-c', false);
    $unrelated = $store->issue('unrelated-package', 'account:owner-c', false);
    $store->revokeForPackage('package-to-revoke');

    $revokedRejected = false;
    try {
        $store->consume($revoked);
    } catch (RuntimeException) {
        $revokedRejected = true;
    }
    if (!$revokedRejected) {
        throw new RuntimeException('Package-scoped revocation left the target token usable.');
    }
    if (($store->consume($unrelated)['package_id'] ?? null) !== 'unrelated-package') {
        throw new RuntimeException('Package-scoped revocation removed an unrelated token.');
    }

    // Corrupt token records must not be silently skipped during revocation, since
    // the store cannot prove that an unreadable record belongs to another package.
    $corruptDirectory = $directory . DIRECTORY_SEPARATOR . 'corrupt';
    if (!mkdir($corruptDirectory, 0700, true)) {
        throw new RuntimeException('Unable to create corrupt token-store fixture.');
    }
    try {
        $corruptStore = new PackageAccessTokenStore($corruptDirectory, 60);
        $corruptToken = $corruptStore->issue('package-corrupt-record', 'account:owner-d', false);
        $corruptPath = $corruptDirectory . DIRECTORY_SEPARATOR . hash('sha256', $corruptToken) . '.json';
        if (file_put_contents($corruptPath, '{"package_id":') === false) {
            throw new RuntimeException('Unable to corrupt token record fixture.');
        }
        $corruptionDetected = false;
        try {
            $corruptStore->revokeForPackage('package-corrupt-record');
        } catch (RuntimeException $exception) {
            $corruptionDetected = str_contains($exception->getMessage(), 'corrupt')
                || str_contains($exception->getMessage(), 'invalid');
        }
        if (!$corruptionDetected) {
            throw new RuntimeException('Token revocation silently ignored a corrupt record.');
        }
    } finally {
        foreach (glob($corruptDirectory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_link($file) || is_file($file)) @unlink($file);
            elseif (is_dir($file)) {
                foreach (glob($file . DIRECTORY_SEPARATOR . '*') ?: [] as $nested) {
                    if (is_link($nested) || is_file($nested)) @unlink($nested);
                }
                @rmdir($file);
            }
        }
        @rmdir($corruptDirectory);
    }


    echo "Package access token regression tests passed.\n";
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_link($file) || is_file($file)) @unlink($file);
    }
    @rmdir($directory);
}
