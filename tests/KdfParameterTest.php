<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageDescriptor as Format;

Format::assertRuntime();
Format::assertKdfParameters(Format::MIN_KDF_OPS, Format::MIN_KDF_MEM_BYTES);
Format::assertKdfParameters(Format::DEFAULT_KDF_OPS, Format::DEFAULT_KDF_MEM_BYTES);
Format::assertKdfParameters(Format::MAX_KDF_OPS, Format::MAX_KDF_MEM_BYTES);
foreach ([
    [Format::MIN_KDF_OPS - 1, Format::MIN_KDF_MEM_BYTES],
    [Format::MAX_KDF_OPS + 1, Format::MAX_KDF_MEM_BYTES],
    [Format::MIN_KDF_OPS, Format::MIN_KDF_MEM_BYTES - 1],
    [Format::MAX_KDF_OPS, Format::MAX_KDF_MEM_BYTES + 1],
] as [$ops, $memory]) {
    $rejected = false;
    try { Format::assertKdfParameters($ops, $memory); } catch (RuntimeException) { $rejected = true; }
    if (!$rejected) throw new RuntimeException('SPKG accepted an out-of-policy KDF profile.');
}
echo "SPKG KDF parameter tests passed.\n";
