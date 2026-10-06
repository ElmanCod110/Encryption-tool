<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageId;

$id = PackageId::generate();
if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
    throw new RuntimeException('Package ID format test failed.');
}
PackageId::assert($id);
try {
    PackageId::assert(str_repeat('a', 47));
    throw new RuntimeException('Invalid package ID was accepted.');
} catch (RuntimeException) {
}

echo "Package ID tests passed.\n";
