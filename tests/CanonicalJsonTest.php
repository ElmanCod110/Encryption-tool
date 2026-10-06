<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\CanonicalJson;

$a = ['z' => 1, 'a' => ['b' => 2, 'a' => 1], 'm' => [3, 2, 1]];
$b = ['m' => [3, 2, 1], 'z' => 1, 'a' => ['a' => 1, 'b' => 2]];
if (!hash_equals(CanonicalJson::encode($a), CanonicalJson::encode($b))) {
    throw new RuntimeException('Canonical JSON is not deterministic.');
}
echo "Canonical JSON tests passed.\n";
