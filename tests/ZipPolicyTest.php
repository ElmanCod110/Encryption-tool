<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\ArchivePolicy;

$policy = new ArchivePolicy(maxEntries: 10, maxSingleFileBytes: 1024, maxTotalUncompressedBytes: 4096, maxDepth: 2, maxNestedArchives: 1);
foreach (['../../evil.txt','/absolute.txt','C:\\evil.txt'] as $path) {
    $thrown = false;
    try { $policy->assertSafePath($path); } catch (Throwable $e) { $thrown = true; }
    if (!$thrown) throw new RuntimeException('Unsafe path accepted: ' . $path);
}
foreach (['FOLD1/file.txt','folder/sub/file.bin','unicodé.txt'] as $path) $policy->assertSafePath($path);
echo "ZIP policy tests passed.\n";
