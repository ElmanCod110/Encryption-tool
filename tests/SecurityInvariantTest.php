<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\V14KeyDerivation;
use SecurePackage\Project\V14Descriptor;
use SecurePackage\Security\Validator;

$salt = random_bytes(32);
$a = V14KeyDerivation::credentialWrapKey('Strong!Password2026', 'gggggggggggA!', $salt);
$b = V14KeyDerivation::credentialWrapKey('Strong!Password2026', 'gggggggggggB!', $salt);
if (hash_equals($a, $b)) throw new RuntimeException('V14 credential separation invariant failed.');
Validator::validatePassword('Strong!Password2026');
Validator::validatePattern('gG7!xY2_Ab9#Qp');
if (V14Descriptor::VERSION !== 14) throw new RuntimeException('V14 version invariant failed.');
sodium_memzero($a); sodium_memzero($b);
echo "V14 security invariants passed.\n";
