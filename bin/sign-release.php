<?php
declare(strict_types=1);

if ($argc !== 3) {
    fwrite(STDERR, "Usage: php bin/sign-release.php <private-key-hex-file> <project-root>\n");
    exit(1);
}
$keyHex = trim((string)file_get_contents($argv[1]));
$key = ctype_xdigit($keyHex) ? hex2bin($keyHex) : false;
if ($key === false || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fwrite(STDERR, "Invalid Ed25519 private key.\n");
    exit(1);
}
$root = realpath($argv[2]);
if ($root === false) {
    fwrite(STDERR, "Project root not found.\n");
    exit(1);
}
$assets = [
    'client-vault.html',
    'client-v13.php',
    'health-v13.php',
    'client/v13/vault-v13.js',
    'client/v13/worker.js',
    'client/v13/vault-v13.css',
];
$publicRoot = $root . DIRECTORY_SEPARATOR . 'public';
$hashes = [];
foreach ($assets as $relative) {
    $path = $publicRoot . DIRECTORY_SEPARATOR . $relative;
    if (!is_file($path)) {
        fwrite(STDERR, "Missing release asset: {$relative}\n");
        exit(1);
    }
    $hashes[$relative] = hash_file('sha256', $path);
}
$manifest = [
    'product' => 'Secure Package',
    'format' => 'SECURE-BROWSER-V13',
    'version' => '13.0.0',
    'author' => 'ElmanCod110',
    'assets' => $hashes,
];
$payload = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
$releaseDir = $root . '/public/release';
if (!is_dir($releaseDir) && !mkdir($releaseDir, 0700, true) && !is_dir($releaseDir)) {
    fwrite(STDERR, "Unable to create release directory.\n");
    exit(1);
}
file_put_contents($releaseDir . '/manifest.json', $payload, LOCK_EX);
file_put_contents($releaseDir . '/manifest.sig', base64_encode(sodium_crypto_sign_detached($payload, $key)) . PHP_EOL, LOCK_EX);
file_put_contents($releaseDir . '/public-key.hex', bin2hex(sodium_crypto_sign_publickey_from_secretkey($key)) . PHP_EOL, LOCK_EX);
echo "V13 release manifest signed successfully.\n";
