<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$root = dirname(__DIR__);
$manifestPath = $root . '/public/release/manifest.json';
$sigPath = $root . '/public/release/manifest.sig';
$pubPath = $root . '/public/release/public-key.hex';

if (!is_file($manifestPath) || !is_file($sigPath) || !is_file($pubPath)) {
    echo "Release integrity tests skipped: unsigned development tree.\n";
    exit(0);
}

$m = file_get_contents($manifestPath);
$sigRaw = file_get_contents($sigPath);
$pubRaw = file_get_contents($pubPath);
$sig = base64_decode(trim((string) $sigRaw), true);
$pub = hex2bin(trim((string) $pubRaw));
if ($m === false || $sig === false || $pub === false) throw new RuntimeException('Release material is unreadable.');
if (!sodium_crypto_sign_verify_detached($sig, $m, $pub)) throw new RuntimeException('Release signature failed.');
$data = json_decode($m, true, 512, JSON_THROW_ON_ERROR);
if (($data['format'] ?? null) !== 'SECURE-BROWSER-V13' || ($data['version'] ?? null) !== '13.0.0') throw new RuntimeException('Release manifest identity failed.');
foreach (($data['assets'] ?? []) as $relative => $expected) {
    $path = $root . '/public/' . $relative;
    if (!is_file($path)) throw new RuntimeException('Release asset missing: ' . $relative);
    $actual = hash_file('sha256', $path);
    if (!hash_equals((string) $expected, $actual)) throw new RuntimeException('Asset hash failed: ' . $relative);
}
echo "Release integrity tests passed.\n";
