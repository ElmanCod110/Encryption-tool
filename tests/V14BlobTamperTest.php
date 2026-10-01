<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;

$root = sys_get_temp_dir() . '/securepkg-v14-blob-tamper-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package';
$restore = $root . '/restore';
mkdir($source . '/nested', 0700, true);
file_put_contents($source . '/nested/data.bin', random_bytes(131072));
$password = 'V14-Strong-Password-2026!';
$pattern = 'V14#Pattern$WithEntropy9';

try {
    $result = (new V14PackageBuilder())->build($source, $package, $password, $pattern, null, true);
    $blob = glob($package . '/blobs/*.bin')[0] ?? null;
    if ($blob === null) throw new RuntimeException('No blob created.');
    $handle = fopen($blob, 'r+b');
    if ($handle === false || fseek($handle, 12) !== 0) throw new RuntimeException('Unable to tamper blob.');
    $byte = fread($handle, 1);
    if ($byte === false || $byte === '') throw new RuntimeException('Unable to read tamper byte.');
    fseek($handle, 12);
    fwrite($handle, chr(ord($byte) ^ 0x01));
    fclose($handle);

    try {
        (new V14PackageReader())->restore($package, $restore, $password, $pattern);
        throw new RuntimeException('Tampered blob was accepted.');
    } catch (Throwable $e) {
        if (is_dir($restore)) throw new RuntimeException('Tampered package left restore output behind.');
    }

    echo "V14 blob tamper and pre-write integrity test passed.\n";
} finally {
    $password = $pattern = '';
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
