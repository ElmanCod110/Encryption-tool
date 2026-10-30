<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageCrypto;
use SecurePackage\Project\StablePackageDescriptor;
use SecurePackage\Security\Validator;

$salt = random_bytes(StablePackageDescriptor::SALT_BYTES);
$packageId = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::PACKAGE_ID_BYTES);
$a = StablePackageCrypto::deriveCredentialKey(
    'Strong!Password2026', 'gG7!xY2_Ab9#Qp', $salt, $packageId,
    StablePackageDescriptor::MIN_KDF_OPS, StablePackageDescriptor::MIN_KDF_MEM_BYTES
);
$b = StablePackageCrypto::deriveCredentialKey(
    'Strong!Password2026', 'gG7!xY2_Ab9#QpX', $salt, $packageId,
    StablePackageDescriptor::MIN_KDF_OPS, StablePackageDescriptor::MIN_KDF_MEM_BYTES
);
if (hash_equals($a, $b)) throw new RuntimeException('SPKG credential separation invariant failed.');
Validator::validatePassword('Strong!Password2026');
Validator::validatePattern('gG7!xY2_Ab9#Qp');
if (strlen(StablePackageDescriptor::MAGIC) !== 8 || StablePackageDescriptor::EXTENSION !== '.spkg') {
    throw new RuntimeException('SPKG format identity invariant failed.');
}
StablePackageDescriptor::assertKdfParameters(
    StablePackageDescriptor::DEFAULT_KDF_OPS,
    StablePackageDescriptor::DEFAULT_KDF_MEM_BYTES
);
sodium_memzero($a);
sodium_memzero($b);
echo "SPKG security invariants passed.\n";
