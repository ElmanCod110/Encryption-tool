<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SecurePackage\Crypto\V14Aead;
use SecurePackage\Crypto\V14KeyDerivation;
use SecurePackage\Crypto\V14Merkle;
use SecurePackage\Crypto\V14Stream;
use SecurePackage\Security\CanonicalJson;
use SecurePackage\Security\Validator;

final class V14PackageReader
{
    public function restore(string $packageDir, string $destinationDir, string $password, string $pattern, ?string $recoveryKey = null): array
    {
        $verifier = new V14PackageVerifier();
        $header = $verifier->assertPackageDirectory($packageDir);
        $root = realpath($packageDir);
        if ($root === false) throw new RuntimeException('Unable to open package.');
        $binding = (string) $header['header_binding'];
        $salt = base64_decode((string) $header['salt'], true);
        if ($salt === false) throw new RuntimeException('Unable to open package.');

        $packageRootKey = null;
        $manifestKey = null;
        $filenameKey = null;
        $fileRootKey = null;
        $credentialKey = null;
        $recoveryKeyRaw = null;
        try {
            if ($recoveryKey !== null && $recoveryKey !== '') {
                $recoveryKeyRaw = self::decodeRecoveryKey($recoveryKey);
                $packageRootKey = V14Aead::unwrapKey($header['key_slots']['recovery'], $recoveryKeyRaw, 'SecurePackage|V14|slot|recovery|' . $header['package_id'] . '|' . $binding);
            } else {
                Validator::validatePassword($password);
                Validator::validatePattern($pattern);
                $credentialKey = V14KeyDerivation::credentialWrapKey($password, $pattern, $salt);
                $packageRootKey = V14Aead::unwrapKey($header['key_slots']['primary'], $credentialKey, 'SecurePackage|V14|slot|primary|' . $header['package_id'] . '|' . $binding);
            }
            if (strlen($packageRootKey) !== V14Descriptor::KEY_BYTES) throw new RuntimeException('Invalid package key.');
            $manifestKey = V14KeyDerivation::deriveSubkey($packageRootKey, 'manifest', $header['package_id']);
            $filenameKey = V14KeyDerivation::deriveSubkey($packageRootKey, 'filename', $header['package_id']);
            $fileRootKey = V14KeyDerivation::deriveSubkey($packageRootKey, 'files', $header['package_id']);

            $manifestPath = $root . DIRECTORY_SEPARATOR . 'manifest.enc';
            $manifestCipher = file_get_contents($manifestPath);
            if ($manifestCipher === false || strlen($manifestCipher) > V14Descriptor::MAX_MANIFEST_BYTES + 64) throw new RuntimeException('Unable to open package.');
            $manifestPlain = V14Aead::open($manifestCipher, $manifestKey, 'SecurePackage|V14|manifest|' . $header['package_id'] . '|' . $binding);
            if (strlen($manifestPlain) > V14Descriptor::MAX_MANIFEST_BYTES) throw new RuntimeException('Manifest exceeds V14 limits.');
            $manifest = json_decode($manifestPlain, true, 64, JSON_THROW_ON_ERROR);
            $this->validateManifest($manifest, $header);

            $complete = json_decode((string) file_get_contents($root . DIRECTORY_SEPARATOR . 'complete.json'), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($complete)) throw new RuntimeException('Package completion record is invalid.');
            $completeKeys = array_keys($complete); sort($completeKeys);
            if ($completeKeys !== ['created_at', 'format', 'header_binding', 'manifest_sha256', 'package_id', 'version'] || ($complete['format'] ?? null) !== V14Descriptor::FORMAT || (int) ($complete['version'] ?? 0) !== V14Descriptor::VERSION || ($complete['package_id'] ?? null) !== $header['package_id'] || ($complete['created_at'] ?? null) !== $header['created_at'] || ($complete['header_binding'] ?? null) !== $binding || !hash_equals((string) ($complete['manifest_sha256'] ?? ''), hash('sha256', $manifestCipher))) {
                throw new RuntimeException('Package completion record is invalid.');
            }

            $blobs = $this->inventoryBlobs($root . DIRECTORY_SEPARATOR . 'blobs');
            $referenced = [];
            $leaves = [];
            foreach ($manifest['nodes'] as $node) {
                if (($node['type'] ?? null) !== 'file') continue;
                $blob = $node['blob'];
                if (isset($referenced[$blob])) throw new RuntimeException('Duplicate blob reference.');
                $referenced[$blob] = true;
                if (!isset($blobs[$blob])) throw new RuntimeException('Manifest references a missing blob.');
                $actualHash = hash_file('sha256', $blobs[$blob]);
                if ($actualHash === false || !hash_equals((string) $node['cipher_hash'], $actualHash)) throw new RuntimeException('Ciphertext integrity check failed.');
                $leaves[] = V14Merkle::leaf((string) $node['id'], (string) $node['cipher_hash'], (int) $node['size']);
            }
            if (count($referenced) !== count($blobs)) throw new RuntimeException('Package contains unreachable blobs.');
            if (!hash_equals((string) $manifest['merkle_root'], V14Merkle::root($leaves))) throw new RuntimeException('Merkle integrity verification failed.');

            if (file_exists($destinationDir)) throw new RuntimeException('Destination directory already exists.');
            if (!mkdir($destinationDir, 0700, true)) throw new RuntimeException('Unable to create destination directory.');
            $created = true;
            try {
                $paths = $this->preflightPaths($manifest, $filenameKey, $header['package_id'], $binding, $destinationDir);
                $directories = [];
                $files = [];
                foreach ($manifest['nodes'] as $node) {
                    $paths[$node['id']]['depth'] = substr_count($paths[$node['id']]['normalized'], '/') + 1;
                    if ($node['type'] === 'dir') $directories[] = $node; else $files[] = $node;
                }
                usort($directories, static fn(array $a, array $b): int => ($paths[$a['id']]['depth'] <=> $paths[$b['id']]['depth']) ?: strcmp($paths[$a['id']]['normalized'], $paths[$b['id']]['normalized']));
                foreach ($directories as $node) {
                    $target = $paths[$node['id']]['target'];
                    if (!mkdir($target, 0700) && !is_dir($target)) throw new RuntimeException('Unable to restore directory.');
                }
                usort($files, static fn(array $a, array $b): int => strcmp($paths[$a['id']]['normalized'], $paths[$b['id']]['normalized']));
                foreach ($files as $node) {
                    $id = $node['id'];
                    $target = $paths[$id]['target'];
                    $fileKey = V14KeyDerivation::deriveFileKey($fileRootKey, $id);
                    try {
                        $blobPath = $blobs[$node['blob']];
                        V14Stream::decryptFile($blobPath, $target, $fileKey, 'SecurePackage|V14|file|' . $header['package_id'] . '|' . $binding . '|' . $id, (int) $node['size']);
                    } finally {
                        sodium_memzero($fileKey);
                    }
                }
            } catch (\Throwable $e) {
                $this->removeDirectory($destinationDir);
                $created = false;
                throw $e;
            }

            return [
                'format' => V14Descriptor::FORMAT,
                'version' => V14Descriptor::VERSION,
                'package_id' => $header['package_id'],
                'nodes' => count($manifest['nodes']),
                'files' => (int) $manifest['files'],
                'directories' => (int) $manifest['directories'],
                'total_plain_bytes' => (int) $manifest['total_plain_bytes'],
                'merkle_root' => $manifest['merkle_root'],
            ];
        } catch (\Throwable $e) {
            throw new RuntimeException('Unable to open V14 package.', 0, $e);
        } finally {
            if ($credentialKey !== null) sodium_memzero($credentialKey);
            if ($packageRootKey !== null) sodium_memzero($packageRootKey);
            if ($manifestKey !== null) sodium_memzero($manifestKey);
            if ($filenameKey !== null) sodium_memzero($filenameKey);
            if ($fileRootKey !== null) sodium_memzero($fileRootKey);
            if ($recoveryKeyRaw !== null) sodium_memzero($recoveryKeyRaw);
        }
    }

    private function validateManifest(array $manifest, array $header): void
    {
        $manifestKeys = array_keys($manifest); sort($manifestKeys);
        if ($manifestKeys !== ['directories', 'files', 'format', 'header_binding', 'merkle_root', 'nodes', 'package_id', 'schema', 'total_plain_bytes', 'version']) throw new RuntimeException('Invalid manifest.');
        if (($manifest['format'] ?? null) !== V14Descriptor::FORMAT || (int) ($manifest['version'] ?? 0) !== V14Descriptor::VERSION || (int) ($manifest['schema'] ?? 0) !== V14Descriptor::SCHEMA || ($manifest['package_id'] ?? null) !== $header['package_id'] || ($manifest['header_binding'] ?? null) !== $header['header_binding']) throw new RuntimeException('Invalid manifest.');
        foreach (['files', 'directories', 'total_plain_bytes'] as $field) if (!isset($manifest[$field]) || !is_int($manifest[$field]) || $manifest[$field] < 0) throw new RuntimeException('Invalid manifest.');
        if (!isset($manifest['nodes']) || !is_array($manifest['nodes']) || $manifest['nodes'] === [] || count($manifest['nodes']) > V14Descriptor::MAX_NODES) throw new RuntimeException('Invalid manifest.');
        if ($manifest['files'] < 1 || $manifest['files'] + $manifest['directories'] !== count($manifest['nodes']) || $manifest['total_plain_bytes'] > V14Descriptor::MAX_TOTAL_PLAIN_BYTES || !isset($manifest['merkle_root']) || !preg_match('/^[a-f0-9]{64}$/', (string) $manifest['merkle_root'])) throw new RuntimeException('Invalid manifest.');
        $ids = [];
        $types = [];
        $total = 0;
        foreach ($manifest['nodes'] as $node) {
            if (!is_array($node)) throw new RuntimeException('Invalid manifest node.');
            $keys = array_keys($node);
            sort($keys);
            $type = (string) ($node['type'] ?? '');
            $expected = $type === 'file' ? ['cipher_hash','blob','id','name','parent','size','type'] : ['id','name','parent','type'];
            $expected2 = $expected;
            sort($expected2);
            if ($keys !== $expected2 || !in_array($type, ['file', 'dir'], true)) throw new RuntimeException('Invalid manifest node.');
            $id = (string) ($node['id'] ?? '');
            if (!preg_match('/^[a-f0-9]{32}$/', $id) || isset($ids[$id])) throw new RuntimeException('Invalid manifest node id.');
            $ids[$id] = true;
            $types[$id] = $type;
            if (!is_string($node['name']) || strlen($node['name']) > 1_000_000 || base64_decode($node['name'], true) === false) throw new RuntimeException('Invalid encrypted name.');
            $parent = $node['parent'] ?? null;
            if ($parent !== null && (!is_string($parent) || !preg_match('/^[a-f0-9]{32}$/', $parent))) throw new RuntimeException('Invalid manifest parent.');
            if ($type === 'file') {
                if (!is_string($node['blob']) || !preg_match('/^[a-f0-9]{48}\.bin$/', $node['blob']) || !preg_match('/^[a-f0-9]{64}$/', (string) $node['cipher_hash']) || !is_int($node['size']) || $node['size'] < 0 || $node['size'] > V14Descriptor::MAX_FILE_BYTES) throw new RuntimeException('Invalid manifest file.');
                $total += $node['size'];
                if ($total > V14Descriptor::MAX_TOTAL_PLAIN_BYTES) throw new RuntimeException('Manifest plaintext total exceeds V14 limits.');
            }
        }
        $files = 0; $dirs = 0;
        foreach ($manifest['nodes'] as $node) {
            $type = $node['type'];
            $parent = $node['parent'];
            if ($parent !== null && (!isset($types[$parent]) || $types[$parent] !== 'dir')) throw new RuntimeException('Manifest parent is not a directory.');
            $type === 'file' ? $files++ : $dirs++;
        }
        if ($files !== $manifest['files'] || $dirs !== $manifest['directories'] || $total !== $manifest['total_plain_bytes']) throw new RuntimeException('Manifest totals are invalid.');
    }

    private function inventoryBlobs(string $dir): array
    {
        $entries = scandir($dir);
        if ($entries === false) throw new RuntimeException('Unable to inventory package blobs.');
        $map = [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            if (!preg_match('/^[a-f0-9]{48}\.bin$/', $entry)) throw new RuntimeException('Invalid package blob name.');
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_link($path) || !is_file($path)) throw new RuntimeException('Invalid package blob.');
            $size = filesize($path);
            if ($size === false || $size < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES + 8 || $size > V14Descriptor::MAX_FILE_BYTES + 64 * 1024 * 1024) throw new RuntimeException('Package blob exceeds limits.');
            $map[$entry] = $path;
            if (count($map) > V14Descriptor::MAX_BLOBS) throw new RuntimeException('Too many package blobs.');
        }
        return $map;
    }

    private function preflightPaths(array $manifest, string $filenameKey, string $packageId, string $binding, string $destinationDir): array
    {
        $ids = [];
        foreach ($manifest['nodes'] as $node) $ids[$node['id']] = $node;
        $resolved = [];
        $all = [];
        foreach ($manifest['nodes'] as $node) {
            $id = $node['id'];
            $parts = [];
            $cursor = $node;
            $guard = 0;
            while ($cursor !== null) {
                if (++$guard > V14Descriptor::MAX_DEPTH) throw new RuntimeException('Manifest hierarchy is too deep.');
                $name = $this->decryptName($cursor['name'], $filenameKey, $packageId, $binding, $cursor['id']);
                $this->assertName($name);
                array_unshift($parts, $name);
                $parent = $cursor['parent'];
                if ($parent === null) { $cursor = null; continue; }
                if (!isset($ids[$parent]) || $ids[$parent]['type'] !== 'dir') throw new RuntimeException('Manifest hierarchy is invalid.');
                $cursor = $ids[$parent];
            }
            $safeParts = [];
            foreach ($parts as $part) $safeParts[] = $part;
            static $casefold = null;
            $casefold ??= static fn(string $value): string => function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
            $normalized = implode('/', array_map($casefold, $safeParts));
            if (isset($all[$normalized])) throw new RuntimeException('Duplicate restored path.');
            $all[$normalized] = ['id' => $id, 'type' => $node['type']];
            $target = $destinationDir . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $safeParts);
            $resolved[$id] = ['target' => $target, 'normalized' => $normalized];
        }
        $pathList = array_keys($all);
        sort($pathList, SORT_STRING);
        for ($i = 1, $n = count($pathList); $i < $n; $i++) {
            $prev = $all[$pathList[$i - 1]];
            $prevPath = $pathList[$i - 1];
            $currentPath = $pathList[$i];
            if (str_starts_with($currentPath, $prevPath . '/') && $prev['type'] === 'file') throw new RuntimeException('File/directory path conflict.');
        }
        // Existing destination conflicts are checked before creating any child path.
        foreach ($resolved as $entry) {
            $target = $entry['target'];
            if (file_exists($target) || is_link($target)) throw new RuntimeException('Restore target already exists.');
        }
        return $resolved;
    }

    private function decryptName(string $encoded, string $filenameKey, string $packageId, string $binding, string $id): string
    {
        $packed = base64_decode($encoded, true);
        if ($packed === false || strlen($packed) > 8192) throw new RuntimeException('Invalid encrypted name.');
        return V14Aead::open($packed, $filenameKey, 'SecurePackage|V14|name|' . $packageId . '|' . $binding . '|' . $id);
    }

    private function assertName(string $name): void
    {
        if ($name === '' || $name === '.' || $name === '..' || strlen($name) > 255 || !preg_match('//u', $name) || str_contains($name, "\0") || str_contains($name, '/') || str_contains($name, '\\') || preg_match('/[\x00-\x1F\x7F:]/u', $name) === 1 || str_ends_with($name, ' ') || str_ends_with($name, '.') || preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i', $name) === 1 || trim($name, ' .') === '') throw new RuntimeException('Unsafe restored name.');
    }

    private static function decodeRecoveryKey(string $encoded): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $encoded)) throw new RuntimeException('Invalid recovery key.');
        $raw = base64_decode(strtr($encoded, '-_', '+/') . '=', true);
        if ($raw === false || strlen($raw) !== V14Descriptor::KEY_BYTES) throw new RuntimeException('Invalid recovery key.');
        return $raw;
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) return;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($path);
    }
}
