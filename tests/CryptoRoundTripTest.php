<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\CryptoEngine;
use SecurePackage\Crypto\KeyDerivation;

$salt = random_bytes(KeyDerivation::SALT_BYTES);
$password = 'Strong!Password2026#';
$patternA = 'Az!71_xYp#42Qw9';
$patternB = 'Az!71_xYp#42Qx9';

$keyA = KeyDerivation::deriveMasterKey($password, $patternA, $salt);
$keyA2 = KeyDerivation::deriveMasterKey($password, $patternA, $salt);
$keyB = KeyDerivation::deriveMasterKey($password, $patternB, $salt);

assert(hash_equals($keyA, $keyA2));
assert(!hash_equals($keyA, $keyB));

$payload = 'SecurePackage cryptographic round-trip test';
$ciphertext = CryptoEngine::encryptString($payload, $keyA, 'test');
assert(CryptoEngine::decryptString($ciphertext, $keyA, 'test') === $payload);

$failed = false;
try {
    CryptoEngine::decryptString($ciphertext, $keyB, 'test');
} catch (Throwable) {
    $failed = true;
}
assert($failed);

echo "Crypto tests passed.\n";
