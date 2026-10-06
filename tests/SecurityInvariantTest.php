<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Crypto\KeyDerivation;
use TCH\Security\Validator;

$salt = random_bytes(32);
$a = KeyDerivation::deriveMasterKey('Strong!Password2026', 'gggggggggggA!', $salt);
$b = KeyDerivation::deriveMasterKey('Strong!Password2026', 'gggggggggggB!', $salt);
if (hash_equals($a, $b)) throw new RuntimeException('Pattern avalanche invariant failed.');

Validator::validatePassword('Strong!Password2026');
Validator::validatePattern('gG7!xY2_Ab9#Qp');
foreach (['123456789012', 'AAAAAAAAAAAA', 'aaaaaaaaaaaa'] as $weak) {
    try {
        Validator::validatePattern($weak);
        throw new RuntimeException('Weak pattern was accepted.');
    } catch (InvalidArgumentException) {
    }
}

echo "Security invariants passed.\n";
