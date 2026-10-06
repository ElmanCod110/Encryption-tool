<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\V12Descriptor;
use SecurePackage\Security\CanonicalJson;

mt_srand(12012012);
for ($i = 0; $i < 5000; $i++) {
    $length = mt_rand(0, 160);
    $value = [];
    for ($j = 0; $j < mt_rand(0, 8); $j++) {
        $key = 'k' . mt_rand(0, 1000);
        $value[$key] = match (mt_rand(0, 4)) {
            0 => null,
            1 => mt_rand(-1000000, 1000000),
            2 => str_repeat(chr(mt_rand(32, 126)), mt_rand(0, 24)),
            3 => [mt_rand(0, 100), mt_rand(0, 100)],
            default => (bool) mt_rand(0, 1),
        };
    }
    $encoded = CanonicalJson::encode($value);
    if ($encoded === '' || strlen($encoded) > 10000) throw new RuntimeException('Unexpected canonical encoding.');
    $candidate = bin2hex(random_bytes(24));
    V12Descriptor::validatePackageId($candidate);
    if ($length > 1000000) throw new RuntimeException('Impossible fuzz state.');
}

$invalid = ['', str_repeat('a', 47), str_repeat('a', 49), strtoupper(str_repeat('a', 48)), str_repeat('z', 48)];
foreach ($invalid as $candidate) {
    try {
        V12Descriptor::validatePackageId($candidate);
        throw new RuntimeException('Invalid package ID accepted.');
    } catch (RuntimeException $e) {
        if ($e->getMessage() !== 'Invalid package identifier.') throw $e;
    }
}
echo "Fuzz security tests passed.\n";
