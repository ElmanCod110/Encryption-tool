<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\V14KeyDerivation;
use SecurePackage\Project\V14Descriptor;

$salt = random_bytes(V14Descriptor::SALT_BYTES);
$key = V14KeyDerivation::credentialWrapKey('Strong!Password2026', 'gG7!xY2_Ab9#Qp', $salt);
if (strlen($key) !== V14Descriptor::KEY_BYTES) throw new RuntimeException('V14 KDF key length failed.');
if (V14Descriptor::kdfProfile()['name'] !== 'argon2id13' || V14Descriptor::kdfProfile()['mem'] < 256 * 1024 * 1024) throw new RuntimeException('V14 KDF profile is too weak.');
sodium_memzero($key);
echo "V14 KDF parameter tests passed.\n";
