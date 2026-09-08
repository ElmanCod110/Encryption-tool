<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\CryptoEngine;
use SecurePackage\Crypto\KeyDerivation;
use SecurePackage\Project\PackageBuilder;
use SecurePackage\Project\PackageReader;

$root = sys_get_temp_dir() . '/securepkg-tamper-test-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package';
mkdir($source, 0700, true);
file_put_contents($source . '/a.txt', random_bytes(200000));
$password = 'Strong!Password2026';
$pattern = 'gG7!xY2_Ab9#Qp';
(new PackageBuilder())->build($source, $package, $password, $pattern);

$blob = glob($package . '/blobs/*.bin')[0];
$data = file_get_contents($blob);
$data[20] = chr(ord($data[20]) ^ 1);
file_put_contents($blob, $data, LOCK_EX);
try {
    (new PackageReader())->restore($package, $root . '/tampered', $password, $pattern);
    throw new RuntimeException('Tampered blob was accepted.');
} catch (Throwable) {
}

$key = random_bytes(KeyDerivation::MASTER_KEY_BYTES);
$cipher = CryptoEngine::encryptString('test', $key, 'aad');
$cipher[7] = chr(ord($cipher[7]) ^ 1);
try {
    CryptoEngine::decryptString($cipher, $key, 'aad');
    throw new RuntimeException('Tampered string was accepted.');
} catch (Throwable) {
}

echo "Tamper detection tests passed.\n";
