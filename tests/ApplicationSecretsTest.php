<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\ApplicationSecrets;

$root = sys_get_temp_dir() . '/spk-secret-test-' . bin2hex(random_bytes(6));
$originalPepper = getenv('SPK_NAME_PEPPER');
// The test exercises the persistent local-secret bootstrap path, so isolate it from the runner environment.
putenv('SPK_NAME_PEPPER');
try {
    $first = ApplicationSecrets::namePepper($root);
    $second = ApplicationSecrets::namePepper($root);
    if (strlen($first) < 32 || !hash_equals($first, $second)) throw new RuntimeException('Local application secret was not persisted safely.');
    $path = $root . '/secrets/name-pepper.bin';
    if (!is_file($path) || filesize($path) !== 32) throw new RuntimeException('Application secret file is invalid.');

    // A persisted pepper is binary; NUL bytes must not make an otherwise valid
    // 32-byte secret unreadable. This deterministic fixture prevents a flaky
    // random-byte-dependent failure.
    $binaryPepper = "\0" . str_repeat('p', 31);
    if (file_put_contents($path, $binaryPepper) !== 32) throw new RuntimeException('Could not write binary pepper fixture.');
    $loadedBinaryPepper = ApplicationSecrets::namePepper($root);
    if (!hash_equals($binaryPepper, $loadedBinaryPepper)) throw new RuntimeException('Binary application pepper was not accepted intact.');

    @unlink($path);
    @rmdir($root . '/secrets');
    @rmdir($root);
    echo "Application secret tests passed.\n";
} finally {
    if ($originalPepper === false) {
        putenv('SPK_NAME_PEPPER');
    } else {
        putenv('SPK_NAME_PEPPER=' . $originalPepper);
    }
}
