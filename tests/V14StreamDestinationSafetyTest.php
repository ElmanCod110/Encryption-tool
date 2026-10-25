<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\V14Stream;

$root = sys_get_temp_dir() . '/securepkg-v14-stream-destination-' . bin2hex(random_bytes(6));
mkdir($root, 0700, true);
$source = $root . '/plain.txt';
$cipher = $root . '/cipher.bin';
$existing = $root . '/existing.bin';
$restore = $root . '/restore.txt';
$key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
$plain = "stream destination safety test\n";
$sentinel = "existing caller-owned data\n";
file_put_contents($source, $plain);
file_put_contents($existing, $sentinel);

try {
    $rejected = false;
    try {
        V14Stream::encryptFile($source, $existing, $key, 'test-aad', strlen($plain));
    } catch (RuntimeException) {
        $rejected = true;
    }
    if (!$rejected) throw new RuntimeException('Encryption accepted an existing destination.');
    if (file_get_contents($existing) !== $sentinel) throw new RuntimeException('Encryption changed an existing destination.');

    V14Stream::encryptFile($source, $cipher, $key, 'test-aad', strlen($plain));
    if (!is_file($cipher)) throw new RuntimeException('Encryption did not create the output file.');

    $rejected = false;
    try {
        V14Stream::decryptFile($cipher, $existing, $key, 'test-aad', strlen($plain));
    } catch (RuntimeException) {
        $rejected = true;
    }
    if (!$rejected) throw new RuntimeException('Decryption accepted an existing destination.');
    if (file_get_contents($existing) !== $sentinel) throw new RuntimeException('Decryption changed an existing destination.');

    $corrupt = $root . '/corrupt.bin';
    file_put_contents($corrupt, 'invalid stream');
    $failed = false;
    try {
        V14Stream::decryptFile($corrupt, $restore, $key, 'test-aad', strlen($plain));
    } catch (RuntimeException) {
        $failed = true;
    }
    if (!$failed) throw new RuntimeException('Decryption accepted a corrupt stream.');
    if (file_exists($restore)) throw new RuntimeException('Failed decryption left a destination file behind.');

    echo "V14 stream destination safety test passed.\n";
} finally {
    sodium_memzero($key);
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $item) {
        $item->isDir() && !$item->isLink()
            ? @rmdir($item->getPathname())
            : @unlink($item->getPathname());
    }
    @rmdir($root);
}
