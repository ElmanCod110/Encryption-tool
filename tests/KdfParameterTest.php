<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\KeyDerivation;

$salt = random_bytes(KeyDerivation::SALT_BYTES);
$key = KeyDerivation::deriveMasterKey('Strong!Password2026', 'gG7!xY2_Ab9#Qp', $salt);
if (strlen($key) !== KeyDerivation::MASTER_KEY_BYTES) {
    throw new RuntimeException('Master key length test failed.');
}
try {
    KeyDerivation::deriveMasterKey('Strong!Password2026', 'gG7!xY2_Ab9#Qp', $salt, KeyDerivation::DEFAULT_OPSLIMIT + 1, KeyDerivation::DEFAULT_MEMLIMIT);
    throw new RuntimeException('Unapproved KDF parameters were accepted.');
} catch (RuntimeException) {
}

echo "KDF parameter tests passed.\n";
