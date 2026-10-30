<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageCrypto;
use SecurePackage\Project\StablePackageDescriptor as Format;

Format::assertRuntime();
$root = Format::randomNonZeroBytes(Format::KEY_BYTES);
$packageId = Format::randomNonZeroBytes(Format::PACKAGE_ID_BYTES);
$coreHash = random_bytes(32);
$manifestKey = StablePackageCrypto::deriveSubkey($root, 'MANIFEST', $packageId);
$fileKey = StablePackageCrypto::deriveSubkey($root, 'FILE-ROOT', $packageId);
if (hash_equals($manifestKey, $fileKey)) throw new RuntimeException('SPKG key-domain separation invariant failed.');

$nonce = random_bytes(Format::NONCE_BYTES);
$plain = "SPKG authenticated-encryption round trip\0\xFF";
$aad = StablePackageCrypto::manifestAad($coreHash);
$cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $aad, $nonce, $manifestKey);
$opened = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $aad, $nonce, $manifestKey);
if (!is_string($opened) || !hash_equals($plain, $opened)) throw new RuntimeException('SPKG AEAD round trip failed.');
$cipher[strlen($cipher) - 1] = chr(ord($cipher[strlen($cipher) - 1]) ^ 1);
if (sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $aad, $nonce, $manifestKey) !== false) {
    throw new RuntimeException('SPKG AEAD accepted tampered ciphertext.');
}
sodium_memzero($root);
sodium_memzero($manifestKey);
sodium_memzero($fileKey);
echo "SPKG cryptographic primitive round-trip tests passed.\n";
