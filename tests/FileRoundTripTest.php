<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\V14Stream;

$root = sys_get_temp_dir() . '/spk-v14-stream-' . bin2hex(random_bytes(6));
@mkdir($root, 0700, true);
try {
    $source = $root . '/source.bin'; $encrypted = $root . '/encrypted.bin'; $restored = $root . '/restored.bin';
    $data = random_bytes(1024 * 1024 + 123);
    file_put_contents($source, $data);
    $key = random_bytes(32);
    V14Stream::encryptFile($source, $encrypted, $key, 'test-file-aad', strlen($data));
    V14Stream::decryptFile($encrypted, $restored, $key, 'test-file-aad', strlen($data));
    if (!hash_equals(hash('sha256', $data), hash_file('sha256', $restored))) throw new RuntimeException('V14 stream round-trip failed.');
    sodium_memzero($key);
    echo "V14 file stream tests passed.\n";
} finally {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    @rmdir($root);
}
