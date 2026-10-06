<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\CanonicalJson;

if ($argc !== 3) {
    fwrite(STDERR, "Usage: php bin/sign-release.php <private-key-hex-file> <project-root>\n");
    exit(1);
}
$keyHex = trim((string) file_get_contents($argv[1]));
$key = ctype_xdigit($keyHex) ? hex2bin($keyHex) : false;
if ($key === false || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fwrite(STDERR, "Invalid Ed25519 private key.\n");
    exit(1);
}
$root = realpath($argv[2]);
if ($root === false || !is_dir($root)) {
    sodium_memzero($key);
    fwrite(STDERR, "Project root not found.\n");
    exit(1);
}

$files = [];
$roots = ['app', 'bin', 'config', 'public', 'bootstrap.php', 'composer.json', 'composer.lock', 'VERSION'];
$exclude = static function (string $relative): bool {
    return str_starts_with($relative, 'public/release/') || str_starts_with($relative, 'public/storage/') || str_starts_with($relative, 'public/uploads/');
};
foreach ($roots as $rootEntry) {
    $absolute = $root . DIRECTORY_SEPARATOR . $rootEntry;
    if (is_file($absolute)) {
        if (!$exclude($rootEntry)) $files[$rootEntry] = hash_file('sha256', $absolute);
        continue;
    }
    if (!is_dir($absolute)) continue;
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($absolute, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if (!$file->isFile() || $file->isLink()) continue;
        $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
        if ($exclude($relative)) continue;
        $hash = hash_file('sha256', $file->getPathname());
        if ($hash === false) { sodium_memzero($key); fwrite(STDERR, "Unable to hash release file: {$relative}\n"); exit(1); }
        $files[$relative] = $hash;
    }
}
ksort($files, SORT_STRING);

$manifest = [
    'product' => 'Secure Package',
    'format' => 'SECURE-PKG-V14',
    'version' => SECURE_PACKAGE_VERSION,
    'author' => 'ElmanCod110',
    'scope' => 'active-source',
    'hash' => 'sha256',
    'files' => $files,
];
$payload = CanonicalJson::encode($manifest);
$releaseDir = $root . '/public/release';
if (!is_dir($releaseDir) && !mkdir($releaseDir, 0700, true) && !is_dir($releaseDir)) {
    sodium_memzero($key);
    fwrite(STDERR, "Unable to create release directory.\n");
    exit(1);
}
file_put_contents($releaseDir . '/manifest.json', $payload, LOCK_EX);
file_put_contents($releaseDir . '/manifest.sig', base64_encode(sodium_crypto_sign_detached($payload, $key)) . PHP_EOL, LOCK_EX);
file_put_contents($releaseDir . '/public-key.hex', bin2hex(sodium_crypto_sign_publickey_from_secretkey($key)) . PHP_EOL, LOCK_EX);
sodium_memzero($key);
echo "V14 active-source release manifest signed successfully.\n";
