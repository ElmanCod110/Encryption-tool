<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Project\PackageBuilder;
use TCH\Project\PackageReader;

$root = sys_get_temp_dir() . '/tch-pkg-test-' . bin2hex(random_bytes(6));
$source = $root . '/source';
$package = $root . '/package';
$restored = $root . '/restored';
mkdir($source . '/FOLD1/deep', 0700, true);
mkdir($source . '/FOLD2', 0700, true);
file_put_contents($source . '/FOLD1/text.txt', "Unicode: پروژه TCH\n" . random_bytes(777));
file_put_contents($source . '/FOLD1/index.php', "<?php echo 'TCH';\n" . random_bytes(2048));
file_put_contents($source . '/FOLD1/deep/empty.bin', '');
file_put_contents($source . '/FOLD2/file.sql', random_bytes(3 * 1024 * 1024 + 17));

$password = 'Strong!Password2026';
$pattern = 'gG7!xY2_Ab9#Qp';
(new PackageBuilder())->build($source, $package, $password, $pattern);
(new PackageReader())->restore($package, $restored, $password, $pattern);

$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($source) + 1));
    $target = $restored . '/' . $rel;
    if (!is_file($target) || hash_file('sha256', $file->getPathname()) !== hash_file('sha256', $target)) {
        throw new RuntimeException('Package round-trip failed for: ' . $rel);
    }
}

try {
    (new PackageReader())->restore($package, $root . '/wrong', $password, 'gG7!xY2_Ab9#Rz');
    throw new RuntimeException('Wrong pattern was accepted.');
} catch (Throwable) {
}

echo "Package round-trip and wrong-pattern tests passed.\n";
