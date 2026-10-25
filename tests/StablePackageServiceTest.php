<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageDescriptor as Format;
use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\StablePackageService;
use SecurePackage\Project\StablePackageWriter;

function stableServiceAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function stableServiceRemoveTree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    foreach (new DirectoryIterator($path) as $entry) {
        if (!$entry->isDot()) stableServiceRemoveTree($entry->getPathname());
    }
    if (!@rmdir($path)) throw new RuntimeException('Unable to clean stable service test directory.');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'stable-package-service-' . bin2hex(random_bytes(8));
$source = $root . DIRECTORY_SEPARATOR . 'source';
$storage = $root . DIRECTORY_SEPARATOR . 'packages';
$restore = $root . DIRECTORY_SEPARATOR . 'restore';
$recoveryRestore = $root . DIRECTORY_SEPARATOR . 'recovery-restore';
$password = 'Stable!ServicePassword2026';
$pattern = 'Stable#ServicePattern2026';

mkdir($source, 0700, true);
mkdir($storage, 0700, true);
$payload = random_bytes(8193);
file_put_contents($source . DIRECTORY_SEPARATOR . 'service.bin', $payload);

try {
    $result = (new StablePackageService(new StablePackageWriter(), $storage))->build(
        $source,
        'stable-service-test',
        $password,
        $pattern,
        true
    );

    $packageId = $result['package_id'] ?? null;
    $packageFile = $result['package_file'] ?? null;
    stableServiceAssert(is_string($packageId) && preg_match('/^[a-f0-9]{48}$/', $packageId) === 1,
        'Stable package service returned an invalid package identifier.');
    stableServiceAssert(is_string($packageFile) && $packageFile === $storage . DIRECTORY_SEPARATOR . $packageId . '.spkg',
        'Stable package service did not publish the canonical single-file extension.');
    stableServiceAssert(is_file($packageFile) && !is_link($packageFile),
        'Stable package service did not publish a regular package file.');
    stableServiceAssert(($result['stats']['files'] ?? null) === 1
        && ($result['stats']['directories'] ?? null) === 0
        && ($result['stats']['nodes'] ?? null) === 1,
        'Stable package service returned incorrect source statistics.');
    stableServiceAssert(is_string($result['recovery_key'] ?? null),
        'Stable package service did not return the requested recovery key.');
    stableServiceAssert(count(glob($storage . DIRECTORY_SEPARATOR . '*') ?: []) === 1,
        'Stable package service created sidecar files or a legacy package directory.');

    $raw = file_get_contents($packageFile);
    stableServiceAssert(is_string($raw) && substr($raw, 0, 8) === Format::MAGIC,
        'Stable package service did not write the frozen binary magic.');
    $header = Format::parseHeader(substr($raw, 0, Format::HEADER_BYTES));
    stableServiceAssert($header['package_id_hex'] === $packageId,
        'Package filename identifier does not match the serialized package identifier.');

    $reader = new StablePackageReader();
    $restored = $reader->restore($packageFile, $restore, $password, $pattern);
    stableServiceAssert(($restored['package_id'] ?? null) === $packageId,
        'Stable package service output could not be restored by package identifier.');
    stableServiceAssert(hash_equals(hash('sha256', $payload), (string) hash_file('sha256', $restore . DIRECTORY_SEPARATOR . 'service.bin')),
        'Stable package service round trip changed source bytes.');

    $recovered = $reader->restore($packageFile, $recoveryRestore, '', '', $result['recovery_key']);
    stableServiceAssert(($recovered['package_id'] ?? null) === $packageId,
        'Stable service recovery-key restore returned a mismatched package identifier.');
    stableServiceAssert(hash_equals(hash('sha256', $payload), (string) hash_file('sha256', $recoveryRestore . DIRECTORY_SEPARATOR . 'service.bin')),
        'Stable service recovery restore changed source bytes.');

    echo "Stable package service integration test passed.\n";
} finally {
    $password = '';
    $pattern = '';
    stableServiceRemoveTree($root);
}
