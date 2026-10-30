<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\V14Aead;
use SecurePackage\Crypto\V14KeyDerivation;
use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Security\CanonicalJson;

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

    // Re-wrap the package root key with credentials that satisfied the historical
    // V14 KDF byte contract but not today's account-creation strength policy.
    $headerPath = $package . '/header.json';
    $header = json_decode((string) file_get_contents($headerPath), true, 32, JSON_THROW_ON_ERROR);
    $recoveryRaw = base64_decode(strtr((string) $result['recovery_key'], '-_', '+/') . '=', true);
    if (!is_string($recoveryRaw) || strlen($recoveryRaw) !== 32) {
        throw new RuntimeException('V14 recovery fixture is invalid.');
    }
    $binding = (string) $header['header_binding'];
    $rootKey = V14Aead::unwrapKey(
        $header['key_slots']['recovery'],
        $recoveryRaw,
        'SecurePackage|V14|slot|recovery|' . $header['package_id'] . '|' . $binding
    );
    $legacyPassword = 'old-pass';
    $legacyPattern = 'grid';
    $legacyCredentialKey = null;
    try {
        $legacyCredentialKey = V14KeyDerivation::credentialWrapKey(
            $legacyPassword,
            $legacyPattern,
            (string) base64_decode((string) $header['salt'], true)
        );
        $header['key_slots']['primary'] = ['type' => 'primary', 'version' => 1] + V14Aead::wrapKey(
            $rootKey,
            $legacyCredentialKey,
            'SecurePackage|V14|slot|primary|' . $header['package_id'] . '|' . $binding
        );
        $encodedHeader = CanonicalJson::encode($header);
        if (file_put_contents($headerPath, $encodedHeader, LOCK_EX) !== strlen($encodedHeader)) {
            throw new RuntimeException('Unable to write V14 legacy-credential fixture.');
        }
    } finally {
        sodium_memzero($rootKey);
        sodium_memzero($recoveryRaw);
        if (is_string($legacyCredentialKey)) sodium_memzero($legacyCredentialKey);
    }

    $legacyRestore = $root . '/restored-legacy-credentials';
    $legacyResult = (new V14PackageReader())->restore(
        $package, $legacyRestore, $legacyPassword, $legacyPattern
    );
    if (($legacyResult['files'] ?? 0) !== 2
        || file_get_contents($legacyRestore . '/hello.txt') !== "V14\n") {
        throw new RuntimeException('V14 package with previously valid credentials was not restored.');
    }
    echo "V14 package round-trip passed.\n";
} finally {
    sodium_memzero($password); sodium_memzero($pattern);
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
