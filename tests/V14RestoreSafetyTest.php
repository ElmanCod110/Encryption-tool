<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;

$root = sys_get_temp_dir() . '/securepkg-v14-restore-safe-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package';
$restore = $root . '/restore';
mkdir($source . '/docs/deep', 0700, true);
file_put_contents($source . '/docs/deep/readme.txt', "V14 restore safety\n");
file_put_contents($source . '/docs/deep/zero.bin', '');
$password = 'V14-Strong-Password-2026!';
$pattern = 'V14#Pattern$WithEntropy9';

try {
    $result = (new V14PackageBuilder())->build($source, $package, $password, $pattern, null, true);
    (new V14PackageReader())->restore($package, $restore, $password, $pattern);
    $expected = hash_file('sha256', $source . '/docs/deep/readme.txt');
    $actual = hash_file('sha256', $restore . '/docs/deep/readme.txt');
    if ($expected === false || $actual === false || !hash_equals($expected, $actual)) throw new RuntimeException('Restore round-trip failed.');
    if (file_get_contents($restore . '/docs/deep/zero.bin') !== '') throw new RuntimeException('Empty file restore failed.');

    try {
        (new V14PackageReader())->restore($package, $restore, $password, $pattern);
        throw new RuntimeException('Existing destination was accepted.');
    } catch (Throwable) {
        // Expected: fail before touching any existing destination content.
    }
    if (file_get_contents($restore . '/docs/deep/readme.txt') === false) throw new RuntimeException('Existing destination was altered.');

    echo "V14 restore safety and non-overwrite test passed.\n";
} finally {
    $password = $pattern = '';
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
