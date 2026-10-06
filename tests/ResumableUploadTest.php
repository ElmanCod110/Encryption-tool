<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Storage\ResumableUploadStore;

$root = sys_get_temp_dir() . '/securepkg-upload-test-' . bin2hex(random_bytes(6));
$store = new ResumableUploadStore($root, 1024 * 1024);
$ownerA = 'account:a'; $ownerB = 'account:b';
$u = $store->initialize(10, $ownerA);
$store->append($u['id'], 0, '12345', $ownerA);
try { $store->append($u['id'], 5, '67890', $ownerB); throw new RuntimeException('Cross-owner upload was accepted.'); } catch (Throwable) {}
$store->append($u['id'], 5, '67890', $ownerA);
$path = $store->finalize($u['id'], $ownerA);
if (!hash_equals('1234567890', (string) file_get_contents($path))) throw new RuntimeException('Upload assembly failed.');
$store->remove($u['id']);
@rmdir($root);
echo "Resumable upload tests passed.\n";
