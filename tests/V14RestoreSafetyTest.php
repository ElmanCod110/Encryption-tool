<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Project\PackageRestoreRejectedException;
use SecurePackage\Project\PackageStorageException;
use SecurePackage\Crypto\V14Stream;

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

    $wrongCredentialRestore = $root . '/wrong-credential-restore';
    try {
        (new V14PackageReader())->restore($package, $wrongCredentialRestore, 'V14-Other-Strong-Password-2026!', $pattern);
        throw new RuntimeException('Wrong credentials were accepted.');
    } catch (PackageRestoreRejectedException) {
        // Invalid credentials are expected input/package failures, not server errors.
    }
    if (file_exists($wrongCredentialRestore)) throw new RuntimeException('Wrong credentials left a restore destination behind.');

    $storageFailureTyped = false;
    try {
        V14Stream::decryptFile($root . '/missing-stream.bin', $root . '/missing-output.bin', str_repeat('k', 32), '', 0);
    } catch (PackageStorageException) {
        $storageFailureTyped = true;
    }
    if (!$storageFailureTyped) throw new RuntimeException('Missing encrypted stream was not classified as a storage failure.');

    $existingContentHash = hash_file('sha256', $restore . '/docs/deep/readme.txt');
    $existingDestinationRejected = false;
    try {
        (new V14PackageReader())->restore($package, $restore, $password, $pattern);
    } catch (PackageStorageException) {
        $existingDestinationRejected = true;
    }
    if (!$existingDestinationRejected) {
        throw new RuntimeException('Existing destination was accepted instead of rejected as a storage conflict.');
    }
    $afterRejectedRestore = hash_file('sha256', $restore . '/docs/deep/readme.txt');
    if ($existingContentHash === false || $afterRejectedRestore === false
        || !hash_equals($existingContentHash, $afterRejectedRestore)) {
        throw new RuntimeException('Existing destination content changed after rejected restore.');
    }

    echo "V14 restore safety and non-overwrite test passed.\n";
} finally {
    $password = $pattern = '';
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
