<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\CanonicalJson;

if ($argc !== 2) {
    fwrite(STDERR, "Usage: php bin/verify-release.php <release-root>\n");
    exit(1);
}
$root = realpath($argv[1]);
if ($root === false) { fwrite(STDERR, "Release root not found.\n"); exit(1); }
$trustedKeyHex = getenv('SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX') ?: '';
if ($trustedKeyHex !== '' && !preg_match('/^[0-9a-fA-F]{64}$/', $trustedKeyHex)) {
    fwrite(STDERR, "Invalid SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX.\n");
    exit(1);
}
$manifestPath = $root . '/public/release/manifest.json';
$sigPath = $root . '/public/release/manifest.sig';
$keyPath = $root . '/public/release/public-key.hex';
$m = @file_get_contents($manifestPath);
$s = @file_get_contents($sigPath);
$p = @file_get_contents($keyPath);
if ($m === false || $s === false || $p === false) { fwrite(STDERR, "Release signature files are incomplete.\n"); exit(1); }
$embeddedKeyHex = trim($p);
$public = hex2bin($trustedKeyHex !== '' ? $trustedKeyHex : $embeddedKeyHex);
$signature = base64_decode(trim($s), true);
if ($public === false || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
    fwrite(STDERR, "Invalid release signature material.\n"); exit(1);
}
if ($trustedKeyHex !== '' && !hash_equals(strtolower($trustedKeyHex), strtolower($embeddedKeyHex))) {
    fwrite(STDERR, "Embedded release key does not match the pinned trust root.\n"); exit(2);
}
if (!sodium_crypto_sign_verify_detached($signature, $m, $public)) {
    fwrite(STDERR, "Release signature: FAILED\n"); exit(2);
}
$data = json_decode($m, true, 512, JSON_THROW_ON_ERROR);
if (($data['format'] ?? null) !== 'SECURE-PKG-V14' || ($data['version'] ?? null) !== '14.0.0' || ($data['scope'] ?? null) !== 'active-source' || ($data['hash'] ?? null) !== 'sha256' || !is_array($data['files'] ?? null) || $data['files'] === []) {
    fwrite(STDERR, "Release manifest identity is invalid.\n"); exit(2);
}
$canonical = CanonicalJson::encode($data);
if (!hash_equals($m, $canonical)) {
    fwrite(STDERR, "Release manifest is not canonical.\n"); exit(2);
}
foreach ($data['files'] as $relative => $expected) {
    if (!is_string($relative) || $relative === '' || str_starts_with($relative, '/') || str_contains($relative, '\\') || preg_match('~(?:^|/)\.\.(?:/|$)~', $relative) || !preg_match('/^[a-f0-9]{64}$/', (string) $expected)) {
        fwrite(STDERR, "Release manifest file entry is invalid.\n"); exit(2);
    }
    $path = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
    if (!is_file($path) || is_link($path)) { fwrite(STDERR, "Release file missing: {$relative}\n"); exit(2); }
    $actual = hash_file('sha256', $path);
    if ($actual === false || !hash_equals((string) $expected, $actual)) { fwrite(STDERR, "Release hash failed: {$relative}\n"); exit(2); }
}
if ($trustedKeyHex === '') fwrite(STDERR, "WARNING: embedded-key verification proves self-consistency only. Set SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX for an external trust root.\n");
echo "Release signature: PASS\nActive-source hashes: PASS\n";
