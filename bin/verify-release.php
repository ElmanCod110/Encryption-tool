<?php
declare(strict_types=1);

if ($argc !== 2) {
    fwrite(STDERR, "Usage: php bin/verify-release.php <release-root>\n");
    exit(1);
}
$root = realpath($argv[1]);
if ($root === false) { fwrite(STDERR, "Release root not found.\n"); exit(1); }
$m = @file_get_contents($root . '/public/release/manifest.json');
$s = @file_get_contents($root . '/public/release/manifest.sig');
$p = @file_get_contents($root . '/public/release/public-key.hex');
if ($m === false || $s === false || $p === false) { fwrite(STDERR, "Release signature files are incomplete.\n"); exit(1); }
$public = hex2bin(trim($p)); $signature = base64_decode(trim($s), true);
if ($public === false || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) { fwrite(STDERR, "Invalid release signature material.\n"); exit(1); }
if (!sodium_crypto_sign_verify_detached($signature, $m, $public)) { fwrite(STDERR, "Release signature: FAILED\n"); exit(2); }
$data = json_decode($m, true, 512, JSON_THROW_ON_ERROR);
foreach (($data['assets'] ?? []) as $relative => $expected) {
    $actual = hash_file('sha256', $root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . $relative);
    if (!hash_equals((string)$expected, $actual)) { fwrite(STDERR, "Asset hash failed: {$relative}\n"); exit(2); }
}
echo "Release signature: PASS\nAsset hashes: PASS\n";
