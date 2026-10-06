<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Crypto\CryptoEngine;
use TCH\Crypto\KeyDerivation;

$root = sys_get_temp_dir() . '/tch-test-' . bin2hex(random_bytes(6));
mkdir($root, 0700, true);
$source = $root . '/source.bin';
$encrypted = $root . '/encrypted.bin';
$restored = $root . '/restored.bin';
$data = random_bytes(3 * 1024 * 1024 + 123);
file_put_contents($source, $data);
$key = random_bytes(KeyDerivation::MASTER_KEY_BYTES);
CryptoEngine::encryptFile($source, $encrypted, $key, 'file|test');
CryptoEngine::decryptFile($encrypted, $restored, $key, 'file|test', strlen($data));
if (!hash_equals(hash_file('sha256', $source), hash_file('sha256', $restored))) {
    throw new RuntimeException('File round-trip failed.');
}
@unlink($source);
@unlink($encrypted);
@unlink($restored);
@rmdir($root);
echo "File round-trip test passed.\n";
