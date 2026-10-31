#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\StablePackageWriter;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spkg-benchmark-' . bin2hex(random_bytes(8));
$source = $root . DIRECTORY_SEPARATOR . 'source';
$package = $root . DIRECTORY_SEPARATOR . 'benchmark.spkg';
$output = $root . DIRECTORY_SEPARATOR . 'restored';
$payload = random_bytes(2 * 1024 * 1024);
$password = bin2hex(random_bytes(24)) . 'Aa!';
$pattern = bin2hex(random_bytes(24)) . '#Bb!';

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) { @unlink($path); return; }
    if (!is_dir($path)) return;
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) $removeTree($entry->getPathname());
    @rmdir($path);
};

try {
    if (!mkdir($source, 0700, true)
        || file_put_contents($source . DIRECTORY_SEPARATOR . 'payload.bin', $payload) !== strlen($payload)) {
        throw new RuntimeException('Unable to prepare the SPKG benchmark fixture.');
    }

    $started = hrtime(true);
    $stats = (new StablePackageWriter())->build($source, $package, $password, $pattern, null, false);
    $buildSeconds = max((hrtime(true) - $started) / 1_000_000_000, 0.000001);

    $started = hrtime(true);
    $restoreStats = (new StablePackageReader())->restore($package, $output, $password, $pattern);
    $restoreSeconds = max((hrtime(true) - $started) / 1_000_000_000, 0.000001);

    $restored = file_get_contents($output . DIRECTORY_SEPARATOR . 'payload.bin');
    if (!is_string($restored) || !hash_equals(hash('sha256', $payload), hash('sha256', $restored))) {
        throw new RuntimeException('SPKG benchmark round-trip integrity check failed.');
    }

    $packageBytes = filesize($package);
    printf("SPKG end-to-end benchmark (2 MiB payload; includes Argon2id credential derivation)\n");
    printf("Build:   %.3f s (%.2f MiB/s including KDF)\n", $buildSeconds, (strlen($payload) / 1048576) / $buildSeconds);
    printf("Restore: %.3f s (%.2f MiB/s including KDF)\n", $restoreSeconds, (strlen($payload) / 1048576) / $restoreSeconds);
    printf("Package: %s bytes; files=%d; restored_files=%d\n", number_format((float) $packageBytes, 0, '.', ''), (int) ($stats['files'] ?? 0), (int) ($restoreStats['files'] ?? 0));
    echo "Round-trip integrity: PASS\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'SPKG benchmark failed: ' . $error->getMessage() . "\n");
    exit(1);
} finally {
    if ($payload !== '') sodium_memzero($payload);
    if ($password !== '') sodium_memzero($password);
    if ($pattern !== '') sodium_memzero($pattern);
    $removeTree($root);
}
