<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\V14Aead;
use SecurePackage\Crypto\V14Stream;

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "Sodium is required.\n");
    exit(1);
}

$root = sys_get_temp_dir() . '/securepkg-v14-bench-' . bin2hex(random_bytes(6));
$plain = $root . '/input.bin';
$cipher = $root . '/cipher.bin';
$restore = $root . '/restore.bin';
$key = random_bytes(32);
$payload = random_bytes(8 * 1024 * 1024);
mkdir($root, 0700, true);
file_put_contents($plain, $payload, LOCK_EX);

try {
    $start = microtime(true);
    $packed = V14Aead::seal($payload, $key, 'SecurePackage|V14|benchmark');
    $aeadSeconds = max(0.000001, microtime(true) - $start);
    echo 'AEAD throughput: ' . number_format((strlen($payload) / 1048576) / $aeadSeconds, 2) . " MiB/s\n";

    $start = microtime(true);
    V14Stream::encryptFile($plain, $cipher, $key, 'SecurePackage|V14|benchmark|stream', strlen($payload), 4 * 1024 * 1024);
    $streamSeconds = max(0.000001, microtime(true) - $start);
    echo 'Secretstream file throughput: ' . number_format((strlen($payload) / 1048576) / $streamSeconds, 2) . " MiB/s\n";

    V14Stream::decryptFile($cipher, $restore, $key, 'SecurePackage|V14|benchmark|stream', strlen($payload));
    if (hash_file('sha256', $plain) !== hash_file('sha256', $restore)) throw new RuntimeException('Benchmark round-trip failed.');
    unset($packed, $payload);
    echo "V14 benchmark completed with round-trip verification.\n";
} finally {
    sodium_memzero($key);
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
