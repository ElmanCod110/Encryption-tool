<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\StablePackageWriter;

$root = sys_get_temp_dir() . '/spkg-tamper-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package.spkg';
$tampered = $root . '/tampered.spkg';
$restore = $root . '/restore';
mkdir($source, 0700, true);
file_put_contents($source . '/data.txt', 'tamper fixture');
$password = 'Strong!Password2026';
$pattern = 'gG7!xY2_Ab9#Qp';
try {
    (new StablePackageWriter())->build($source, $package, $password, $pattern, null, false);
    $bytes = file_get_contents($package);
    if (!is_string($bytes) || strlen($bytes) < 8) throw new RuntimeException('SPKG fixture was not created.');
    $bytes[0] = chr(ord($bytes[0]) ^ 1);
    file_put_contents($tampered, $bytes);
    $rejected = false;
    try { (new StablePackageReader())->restore($tampered, $restore, $password, $pattern); }
    catch (RuntimeException) { $rejected = true; }
    if (!$rejected) throw new RuntimeException('SPKG reader accepted a corrupted format marker.');
    if (file_exists($restore)) throw new RuntimeException('Rejected SPKG left a restore directory behind.');
    echo "SPKG tamper-detection tests passed.\n";
} finally {
    sodium_memzero($password);
    sodium_memzero($pattern);
    $remove = static function (string $path) use (&$remove): void {
        if (is_link($path) || is_file($path)) { @unlink($path); return; }
        if (!is_dir($path)) return;
        foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) $remove($entry->getPathname());
        @rmdir($path);
    };
    $remove($root);
}
