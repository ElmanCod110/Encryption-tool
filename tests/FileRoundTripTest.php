<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\StablePackageWriter;

$root = sys_get_temp_dir() . '/spkg-file-roundtrip-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/roundtrip.spkg';
$restore = $root . '/restored';
mkdir($source . '/nested', 0700, true);
$payload = random_bytes(512 * 1024 + 19);
file_put_contents($source . '/nested/data.bin', $payload);
file_put_contents($source . '/readme.txt', "SPKG file round trip\n");
$password = 'Strong!Password2026';
$pattern = 'gG7!xY2_Ab9#Qp';
try {
    $created = (new StablePackageWriter())->build($source, $package, $password, $pattern, null, false);
    $restored = (new StablePackageReader())->restore($package, $restore, $password, $pattern, null, $created['package_id']);
    if (file_get_contents($restore . '/nested/data.bin') !== $payload
        || file_get_contents($restore . '/readme.txt') !== "SPKG file round trip\n"
        || ($restored['files'] ?? 0) !== 2) {
        throw new RuntimeException('SPKG file round trip changed package content.');
    }
    echo "SPKG file round-trip tests passed.\n";
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
