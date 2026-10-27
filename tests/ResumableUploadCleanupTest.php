<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Storage\ResumableUploadStore;

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-upload-cleanup-' . bin2hex(random_bytes(8));
$root = $base . DIRECTORY_SEPARATOR . 'uploads';
$outside = $base . DIRECTORY_SEPARATOR . 'outside';
if (!mkdir($root, 0700, true) || !mkdir($outside, 0700, true)) {
    throw new RuntimeException('Unable to create upload cleanup fixtures.');
}

try {
    $store = new ResumableUploadStore($root, 1024, 60);
    $upload = $store->initialize(10, 'owner-test');
    $statePath = $root . DIRECTORY_SEPARATOR . $upload['id'] . DIRECTORY_SEPARATOR . 'state.json';
    $state = json_decode((string) file_get_contents($statePath), true, 16, JSON_THROW_ON_ERROR);
    $state['created_at'] = time() - 120;
    file_put_contents($statePath, json_encode($state, JSON_THROW_ON_ERROR), LOCK_EX);
    $store->cleanup();
    if (file_exists($root . DIRECTORY_SEPARATOR . $upload['id'])) {
        throw new RuntimeException('Expired upload was not removed.');
    }

    $outsideFile = $outside . DIRECTORY_SEPARATOR . 'keep.txt';
    file_put_contents($outsideFile, 'must survive cleanup');
    $linkId = str_repeat('a', 48);
    $linkPath = $root . DIRECTORY_SEPARATOR . $linkId;
    if (@symlink($outside, $linkPath)) {
        $store->cleanup();
        if (is_link($linkPath) || !is_file($outsideFile)) {
            throw new RuntimeException('Upload cleanup followed a symlink outside its storage root.');
        }
    }

    $direct = $store->initialize(10, 'owner-direct-cleanup');
    $directDir = $root . DIRECTORY_SEPARATOR . $direct['id'];
    if (!mkdir($directDir . DIRECTORY_SEPARATOR . 'nested', 0700, true)
        || file_put_contents($directDir . DIRECTORY_SEPARATOR . 'nested' . DIRECTORY_SEPARATOR . 'inside.txt', 'remove me') === false) {
        throw new RuntimeException('Unable to prepare nested upload cleanup fixture.');
    }
    $externalKeep = $outside . DIRECTORY_SEPARATOR . 'survive-direct-remove.txt';
    file_put_contents($externalKeep, 'outside upload storage');
    $nestedLink = $directDir . DIRECTORY_SEPARATOR . 'nested' . DIRECTORY_SEPARATOR . 'external-link';
    if (@symlink($outside, $nestedLink)) {
        $store->remove($direct['id']);
        if (file_exists($directDir) || is_link($directDir)) {
            throw new RuntimeException('Direct upload removal left owned storage behind.');
        }
        if (!is_file($externalKeep) || file_get_contents($externalKeep) !== 'outside upload storage') {
            throw new RuntimeException('Direct upload removal followed a nested symlink.');
        }
    } else {
        $store->remove($direct['id']);
        if (file_exists($directDir) || is_link($directDir)) {
            throw new RuntimeException('Direct upload removal failed without a symlink fixture.');
        }
    }

    $invalidIdRejected = false;
    try {
        $store->remove('../outside');
    } catch (RuntimeException) {
        $invalidIdRejected = true;
    }
    if (!$invalidIdRejected) {
        throw new RuntimeException('Invalid upload cleanup identifier was silently ignored.');
    }

    echo "Resumable upload cleanup tests passed.\n";
} finally {
    foreach ([$root, $outside] as $directory) {
        foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $item) {
            if (is_link($item) || is_file($item)) @unlink($item);
            elseif (is_dir($item)) {
                foreach (glob($item . DIRECTORY_SEPARATOR . '*') ?: [] as $child) @unlink($child);
                @rmdir($item);
            }
        }
        @rmdir($directory);
    }
    @rmdir($base);
}
