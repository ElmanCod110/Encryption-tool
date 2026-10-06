<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$pubPath = $root . '/public/release/public-key.hex';
$manifestPath = $root . '/public/release/manifest.json';
$sigPath = $root . '/public/release/manifest.sig';
if (!is_file($pubPath) || !is_file($manifestPath) || !is_file($sigPath)) {
    echo "Release trust-root test skipped: unsigned development tree.\n";
    exit(0);
}
$key = trim((string) file_get_contents($pubPath));
if (!preg_match('/^[0-9a-f]{64}$/', $key)) throw new RuntimeException('Embedded release key is malformed.');
$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/bin/verify-release.php') . ' ' . escapeshellarg($root);
putenv('SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX=' . $key);
$output = [];
$code = 0;
exec($cmd . ' 2>&1', $output, $code);
putenv('SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX');
if ($code !== 0 || !str_contains(implode("\n", $output), 'Release signature: PASS')) throw new RuntimeException('Pinned release trust-root verification failed.');
echo "Pinned release trust-root test passed.\n";
