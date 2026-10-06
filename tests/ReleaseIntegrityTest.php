<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\CanonicalJson;

$root = dirname(__DIR__);
$manifestPath = $root . '/public/release/manifest.json';
$sigPath = $root . '/public/release/manifest.sig';
$pubPath = $root . '/public/release/public-key.hex';

if (!is_file($manifestPath) || !is_file($sigPath) || !is_file($pubPath)) {
    echo "Release integrity tests skipped: unsigned development tree.\n";
    exit(0);
}
$m = file_get_contents($manifestPath);
$sig = base64_decode(trim((string) file_get_contents($sigPath)), true);
$pub = hex2bin(trim((string) file_get_contents($pubPath)));
if ($m === false || $sig === false || $pub === false) throw new RuntimeException('Release material is unreadable.');
if (!sodium_crypto_sign_verify_detached($sig, $m, $pub)) throw new RuntimeException('Release signature failed.');
$data = json_decode($m, true, 512, JSON_THROW_ON_ERROR);
if (($data['format'] ?? null) !== 'SECURE-PKG-V14' || ($data['version'] ?? null) !== '14.0.0' || ($data['scope'] ?? null) !== 'active-source') throw new RuntimeException('Release manifest identity failed.');
if (!hash_equals($m, CanonicalJson::encode($data))) throw new RuntimeException('Release manifest is not canonical.');
foreach (($data['files'] ?? []) as $relative => $expected) {
    $path = $root . '/' . str_replace('/', DIRECTORY_SEPARATOR, $relative);
    if (!is_file($path) || is_link($path)) throw new RuntimeException('Release file missing: ' . $relative);
    $actual = hash_file('sha256', $path);
    if ($actual === false || !hash_equals((string) $expected, $actual)) throw new RuntimeException('Release hash failed: ' . $relative);
}
echo "V14 release integrity tests passed.\n";
