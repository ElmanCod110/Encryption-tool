<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageWriter;

$root = sys_get_temp_dir() . '/spkg-no-overwrite-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$output = $root . '/existing.spkg';
$sentinel = "preserve-this-existing-SPKG\n";
mkdir($source, 0700, true);
file_put_contents($source . '/hello.txt', 'stable writer fixture');
file_put_contents($output, $sentinel);
try {
    $rejected = false;
    try {
        (new StablePackageWriter())->build(
            $source,
            $output,
            'Strong!Password2026',
            'gG7!xY2_Ab9#Qp',
            null,
            false
        );
    } catch (RuntimeException) {
        $rejected = true;
    }
    if (!$rejected) throw new RuntimeException('Stable writer accepted an existing destination.');
    if (file_get_contents($output) !== $sentinel) {
        throw new RuntimeException('Stable writer modified an existing destination.');
    }
    echo "SPKG writer no-overwrite test passed.\n";
} finally {
    foreach (glob($source . '/*') ?: [] as $path) if (is_file($path) && !is_link($path)) @unlink($path);
    @rmdir($source);
    @unlink($output);
    @rmdir($root);
}
