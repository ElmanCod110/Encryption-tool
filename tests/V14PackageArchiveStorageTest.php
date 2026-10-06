<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    echo "V14 archive-only storage test skipped: Zip extension unavailable.
";
    exit(0);
}

$root = sys_get_temp_dir() . '/securepkg-v14-archive-storage-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package';
$archive = $root . '/package.spkg14';
$restore = $root . '/restore';
mkdir($source, 0700, true);
file_put_contents($source . '/hello.txt', 'archive-only storage\n');

try {
    $built = (new V14PackageBuilder())->build($source, $package, 'Storage-Test-Password-2026!', 'Storage#Pattern$2026', str_repeat('a', 48), true);
    (new PackageArchive())->create($package, $archive);
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($package, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    @rmdir($package);
    if (is_dir($package)) throw new RuntimeException('Extracted package directory was not removed after archive creation.');
    if (!is_file($archive)) throw new RuntimeException('Portable V14 archive is missing.');
    $extracted = $root . '/extracted';
    (new PackageArchive())->extract($archive, $extracted);
    (new V14PackageReader())->restore($extracted, $restore, 'Storage-Test-Password-2026!', 'Storage#Pattern$2026');
    if (file_get_contents($restore . '/hello.txt') !== 'archive-only storage\n') throw new RuntimeException('Archive-only restore content mismatch.');
    echo "V14 archive-only storage test passed.\n";
} finally {
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
