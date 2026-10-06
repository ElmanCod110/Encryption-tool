<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\V14Aead;
use SecurePackage\Crypto\V14KeyDerivation;

$salt = random_bytes(32);
$password = 'Strong!Password2026#';
$patternA = 'Az!71_xYp#42Qw9';
$patternB = 'Az!71_xYp#42Qx9';
$keyA = V14KeyDerivation::credentialWrapKey($password, $patternA, $salt);
$keyA2 = V14KeyDerivation::credentialWrapKey($password, $patternA, $salt);
$keyB = V14KeyDerivation::credentialWrapKey($password, $patternB, $salt);
if (!hash_equals($keyA, $keyA2) || hash_equals($keyA, $keyB)) throw new RuntimeException('V14 KDF invariant failed.');
$cipher = V14Aead::seal('SecurePackage V14 round-trip', $keyA, 'test-aad');
if (V14Aead::open($cipher, $keyA, 'test-aad') !== 'SecurePackage V14 round-trip') throw new RuntimeException('V14 AEAD round-trip failed.');
try { V14Aead::open($cipher, $keyB, 'test-aad'); throw new RuntimeException('Tampered key accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() === 'Tampered key accepted.') throw $e; }
sodium_memzero($keyA); sodium_memzero($keyA2); sodium_memzero($keyB);
echo "V14 crypto tests passed.\n";
