<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\RestoreTokenStore;

$tempRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-restore-ttl-' . bin2hex(random_bytes(8));
$tokenDir = $tempRoot . DIRECTORY_SEPARATOR . 'restore-tokens';
$restoreDir = $tempRoot . DIRECTORY_SEPARATOR . 'restore-' . bin2hex(random_bytes(8));
if (!mkdir($restoreDir, 0700, true)) throw new RuntimeException('Unable to create restore test directory.');
if (!mkdir($tokenDir, 0700, true)) throw new RuntimeException('Unable to create token test directory.');
file_put_contents($restoreDir . DIRECTORY_SEPARATOR . 'sentinel.txt', 'temporary plaintext');

try {
    $store = new RestoreTokenStore($tokenDir, 900);
    $token = $store->issue($restoreDir);
    $recordPath = $tokenDir . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    $record = json_decode((string) file_get_contents($recordPath), true, 16, JSON_THROW_ON_ERROR);
    $record['expires_at'] = time() - 1;
    file_put_contents($recordPath, json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX);

    $store->cleanup();
    if (file_exists($recordPath)) throw new RuntimeException('Expired restore token was not removed.');
    if (file_exists($restoreDir) || is_link($restoreDir)) {
        throw new RuntimeException('Expired restore plaintext directory was not removed.');
    }

    echo "Restore token cleanup regression tests passed.\n";
} finally {
    foreach ([$tokenDir, $tempRoot] as $directory) {
        if (!is_dir($directory)) continue;
        foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $item) {
            if (is_link($item) || is_file($item)) @unlink($item);
            elseif (is_dir($item)) {
                foreach (glob($item . DIRECTORY_SEPARATOR . '*') ?: [] as $child) @unlink($child);
                @rmdir($item);
            }
        }
        @rmdir($directory);
    }
}
