<?php
declare(strict_types=1);

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
$m = @file_get_contents($root . '/public/release/manifest.json');
$s = @file_get_contents($root . '/public/release/manifest.sig');
$p = @file_get_contents($root . '/public/release/public-key.hex');
if ($m === false || $s === false || $p === false) { fwrite(STDERR, "Release signature files are incomplete.\n"); exit(1); }
$embeddedKeyHex = trim($p);
$public = hex2bin($trustedKeyHex !== '' ? $trustedKeyHex : $embeddedKeyHex);
$signature = base64_decode(trim($s), true);
if ($public === false || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) { fwrite(STDERR, "Invalid release signature material.\n"); exit(1); }
if ($trustedKeyHex !== '' && !hash_equals(strtolower($trustedKeyHex), strtolower($embeddedKeyHex))) { fwrite(STDERR, "Embedded release key does not match the pinned trust root.\n"); exit(2); }
if (!sodium_crypto_sign_verify_detached($signature, $m, $public)) { fwrite(STDERR, "Release signature: FAILED\n"); exit(2); }
$data = json_decode($m, true, 512, JSON_THROW_ON_ERROR);
if (($data['format'] ?? null) !== 'SECURE-BROWSER-V13' || ($data['version'] ?? null) !== '13.0.0' || !is_array($data['assets'] ?? null) || count($data['assets']) !== 6) {
    fwrite(STDERR, "Release manifest identity is invalid.\n");
    exit(2);
}
foreach ($data['assets'] as $relative => $expected) {
    if (!is_string($relative) || preg_match('~(^/|\\|(?:^|/)[.]{1,2}(?:/|$))~', $relative) || !preg_match('/^[a-f0-9]{64}$/', (string) $expected)) {
        fwrite(STDERR, "Release manifest asset entry is invalid.\n");
        exit(2);
    }
    $path = $root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . $relative;
    if (!is_file($path)) {
        fwrite(STDERR, "Release asset missing: {$relative}\n");
        exit(2);
    }
    $actual = hash_file('sha256', $path);
    if (!hash_equals((string)$expected, $actual)) { fwrite(STDERR, "Asset hash failed: {$relative}\n"); exit(2); }
}
if ($trustedKeyHex === '') fwrite(STDERR, "WARNING: embedded-key verification proves self-consistency only. Set SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX for an external trust root.\n");
echo "Release signature: PASS\nAsset hashes: PASS\n";
