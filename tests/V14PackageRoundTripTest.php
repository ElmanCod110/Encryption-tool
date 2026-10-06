<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;

$root = sys_get_temp_dir() . '/spk-v14-round-' . bin2hex(random_bytes(6));
$source = $root . '/source'; $package = $root . '/package'; $restored = $root . '/restored';
@mkdir($source . '/nested', 0700, true); @mkdir($package, 0700, true);
file_put_contents($source . '/hello.txt', "V14\n");
file_put_contents($source . '/nested/data.bin', random_bytes(12345));
$password = 'Strong!Password2026#'; $pattern = 'Az!71_xYp#42Qw9';
try {
    $result = (new V14PackageBuilder())->build($source, $package, $password, $pattern, str_repeat('a',48), true);
    if ($result['version'] !== 14 || !is_string($result['merkle_root']) || $result['recovery_key'] === null) throw new RuntimeException('V14 build failed.');
    $restoredResult = (new V14PackageReader())->restore($package, $restored, $password, $pattern);
    if (($restoredResult['files'] ?? 0) !== 2 || file_get_contents($restored . '/hello.txt') !== "V14\n") throw new RuntimeException('V14 restore failed.');
    echo "V14 package round-trip passed.\n";
} finally {
    sodium_memzero($password); sodium_memzero($pattern);
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
