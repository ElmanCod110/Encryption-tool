<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Storage\ResumableUploadStore;

$root = sys_get_temp_dir() . '/secure-package-v5-upload-' . bin2hex(random_bytes(5));
$store = new ResumableUploadStore($root, 1024 * 1024, 3600);
$owner = 'session:test-owner';
$data = random_bytes(8192);
$sum = hash('sha256', $data);
$u = $store->initialize(strlen($data), $owner, $sum);
$store->append($u['id'], 0, $data, $owner);
$file = $store->finalize($u['id'], $owner);
if (!is_file($file) || !hash_equals($sum, hash_file('sha256', $file))) throw new RuntimeException('Checksum verification failed.');

echo "Upload checksum tests passed.\n";
