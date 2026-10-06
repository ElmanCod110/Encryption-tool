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

final class V14PackageBuilder
{
    public function build(string $sourceDir, string $packageDir, string $password, string $pattern, ?string $packageId = null, bool $createRecovery = true): array
    {
        Validator::validatePassword($password);
        Validator::validatePattern($pattern);
        $sourceDir = $this->canonicalDirectory($sourceDir);
        $packageId ??= PackageId::generate();
        PackageId::assert($packageId);
        $this->preparePackageDirectory($packageDir);

        $salt = random_bytes(V14Descriptor::SALT_BYTES);
        $rootKey = random_bytes(V14Descriptor::KEY_BYTES);
        $credentialKey = V14KeyDerivation::credentialWrapKey($password, $pattern, $salt);
        $recoveryKey = $createRecovery ? random_bytes(V14Descriptor::KEY_BYTES) : null;
        $manifestKey = V14KeyDerivation::deriveSubkey($rootKey, 'manifest', $packageId);
        $filenameKey = V14KeyDerivation::deriveSubkey($rootKey, 'filename', $packageId);
        $fileRootKey = V14KeyDerivation::deriveSubkey($rootKey, 'files', $packageId);

        $createdAt = gmdate('Y-m-d\TH:i:s\Z');
        $core = [
            'format' => V14Descriptor::FORMAT,
            'version' => V14Descriptor::VERSION,
            'schema' => V14Descriptor::SCHEMA,
            'package_id' => $packageId,
            'created_at' => $createdAt,
            'salt' => base64_encode($salt),
            'crypto' => [
                'kdf' => V14Descriptor::kdfProfile(),
                'aead' => 'xchacha20poly1305-ietf',
                'key_wrap' => 'xchacha20poly1305-ietf',
                'stream' => 'secretstream-xchacha20poly1305',
                'key_separation' => 'HKDF-SHA-256',
                'hash' => 'sha256',
            ],
        ];
        $binding = V14KeyDerivation::headerBinding($core);
        $primary = V14Aead::wrapKey($rootKey, $credentialKey, 'SecurePackage|V14|slot|primary|' . $packageId . '|' . $binding);
        $recoverySlot = $recoveryKey === null ? null : V14Aead::wrapKey($rootKey, $recoveryKey, 'SecurePackage|V14|slot|recovery|' . $packageId . '|' . $binding);
        $header = $core + [
            'header_binding' => $binding,
            'key_slots' => [
                'primary' => ['type' => 'primary', 'version' => 1] + $primary,
                'recovery' => $recoverySlot === null ? null : ['type' => 'recovery', 'version' => 1] + $recoverySlot,
            ],
        ];

        $manifest = [
            'format' => V14Descriptor::FORMAT,
            'version' => V14Descriptor::VERSION,
            'schema' => V14Descriptor::SCHEMA,
            'package_id' => $packageId,
            'header_binding' => $binding,
            'files' => 0,
            'directories' => 0,
            'nodes' => [],
            'total_plain_bytes' => 0,
            'merkle_root' => null,
        ];

        $dirMap = ['' => null];
        $usedNames = [];
        $leaves = [];
        $totalPlain = 0;

        try {
            $this->writeJson($packageDir . DIRECTORY_SEPARATOR . 'header.json', $header);
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($sourceDir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $entry) {
                $this->assertEntry($entry);
                $relative = $this->relativePath($sourceDir, $entry->getPathname());
                $parentRelative = dirname($relative);
                $parentRelative = $parentRelative === '.' ? '' : str_replace('\\', '/', $parentRelative);
                $parentId = $dirMap[$parentRelative] ?? null;
                if ($parentRelative !== '' && $parentId === null) throw new RuntimeException('Manifest parent order is invalid.');
                $name = basename($relative);
                $this->assertName($name);
                $nameFold = function_exists('mb_strtolower') ? mb_strtolower($name, 'UTF-8') : strtolower($name);
                $nameKey = ($parentId ?? 'root') . "\0" . $nameFold;
                if (isset($usedNames[$nameKey])) throw new RuntimeException('Duplicate directory entry detected.');
                $usedNames[$nameKey] = true;

                $id = bin2hex(random_bytes(16));
                $encryptedName = base64_encode(V14Aead::seal($name, $filenameKey, 'SecurePackage|V14|name|' . $packageId . '|' . $binding . '|' . $id));

                if ($entry->isDir()) {
                    if ($manifest['directories'] + $manifest['files'] >= V14Descriptor::MAX_NODES) throw new RuntimeException('Package contains too many nodes.');
                    $dirMap[$relative] = $id;
                    $manifest['directories']++;
                    $manifest['nodes'][] = ['id' => $id, 'parent' => $parentId, 'type' => 'dir', 'name' => $encryptedName];
                    continue;
                }

                $size = (int) $entry->getSize();
                if ($size < 0 || $size > V14Descriptor::MAX_FILE_BYTES) throw new RuntimeException('A file exceeds the V14 size limit.');
                $totalPlain += $size;
                if ($totalPlain > V14Descriptor::MAX_TOTAL_PLAIN_BYTES) throw new RuntimeException('Package exceeds the V14 plaintext limit.');
                if ($manifest['directories'] + $manifest['files'] >= V14Descriptor::MAX_NODES) throw new RuntimeException('Package contains too many nodes.');
                $blobId = bin2hex(random_bytes(24)) . '.bin';
                $blobPath = $packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blobId;
                $fileKey = V14KeyDerivation::deriveFileKey($fileRootKey, $id);
                V14Stream::encryptFile($entry->getPathname(), $blobPath, $fileKey, 'SecurePackage|V14|file|' . $packageId . '|' . $binding . '|' . $id, $size);
                sodium_memzero($fileKey);
                $cipherHash = hash_file('sha256', $blobPath);
                if ($cipherHash === false || !preg_match('/^[a-f0-9]{64}$/', $cipherHash)) throw new RuntimeException('Unable to hash encrypted file.');
                $manifest['files']++;
                $manifest['nodes'][] = [
                    'id' => $id,
                    'parent' => $parentId,
                    'type' => 'file',
                    'name' => $encryptedName,
                    'blob' => $blobId,
                    'size' => $size,
                    'cipher_hash' => $cipherHash,
                ];
                $leaves[] = \SecurePackage\Crypto\V14Merkle::leaf($id, $cipherHash, $size);
            }

            if ($manifest['files'] === 0) throw new RuntimeException('Cannot create an empty package.');
            $manifest['total_plain_bytes'] = $totalPlain;
            $manifest['merkle_root'] = \SecurePackage\Crypto\V14Merkle::root($leaves);
            $manifestPlain = CanonicalJson::encode($manifest);
            if (strlen($manifestPlain) > V14Descriptor::MAX_MANIFEST_BYTES) throw new RuntimeException('Manifest exceeds V14 limits.');
            $manifestCipher = V14Aead::seal($manifestPlain, $manifestKey, 'SecurePackage|V14|manifest|' . $packageId . '|' . $binding);
            $this->writeBytes($packageDir . DIRECTORY_SEPARATOR . 'manifest.enc', $manifestCipher);

            $this->writeJson($packageDir . DIRECTORY_SEPARATOR . 'complete.json', [
                'format' => V14Descriptor::FORMAT,
                'version' => V14Descriptor::VERSION,
                'package_id' => $packageId,
                'header_binding' => $binding,
                'manifest_sha256' => hash('sha256', $manifestCipher),
                'created_at' => $createdAt,
            ]);

            return [
                'format' => V14Descriptor::FORMAT,
                'version' => V14Descriptor::VERSION,
                'package_id' => $packageId,
                'nodes' => count($manifest['nodes']),
                'files' => $manifest['files'],
                'directories' => $manifest['directories'],
                'total_plain_bytes' => $totalPlain,
                'merkle_root' => $manifest['merkle_root'],
                'recovery_key' => $recoveryKey === null ? null : self::encodeRecoveryKey($recoveryKey),
            ];
        } catch (\Throwable $e) {
            $this->removeDirectory($packageDir);
            throw $e;
        } finally {
            sodium_memzero($rootKey);
            sodium_memzero($credentialKey);
            sodium_memzero($manifestKey);
            sodium_memzero($filenameKey);
            sodium_memzero($fileRootKey);
            if ($recoveryKey !== null) sodium_memzero($recoveryKey);
        }
    }

    private static function encodeRecoveryKey(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function canonicalDirectory(string $path): string
    {
        $real = realpath($path);
        if ($real === false || !is_dir($real)) throw new RuntimeException('Source directory does not exist.');
        return rtrim($real, DIRECTORY_SEPARATOR);
    }

    private function assertEntry($entry): void
    {
        if ($entry->isLink() || $entry->isDir() && $entry->isLink()) throw new RuntimeException('Symbolic links are not supported.');
        if (!$entry->isDir() && !$entry->isFile()) throw new RuntimeException('Unsupported filesystem entry encountered.');
    }

    private function assertName(string $name): void
    {
        if ($name === '' || $name === '.' || $name === '..' || strlen($name) > 255 || preg_match('//u', $name) !== 1 || str_contains($name, "\0") || str_contains($name, '/') || str_contains($name, '\\') || preg_match('/[\x00-\x1F\x7F:]/u', $name) === 1 || str_ends_with($name, ' ') || str_ends_with($name, '.') || preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i', $name) === 1) throw new RuntimeException('Unsafe filesystem name.');
    }

    private function relativePath(string $base, string $path): string
    {
        $base = rtrim(str_replace('\\', '/', $base), '/') . '/';
        $real = realpath($path);
        if ($real === false) throw new RuntimeException('Unable to resolve source path.');
        $path = str_replace('\\', '/', $real);
        if (!str_starts_with($path, $base)) throw new RuntimeException('Filesystem entry escaped the source directory.');
        $relative = ltrim(substr($path, strlen($base)), '/');
        if ($relative === '' || str_contains($relative, "\0") || preg_match('#(?:^|/)\.\.(?:/|$)#', $relative)) throw new RuntimeException('Invalid relative path.');
        return $relative;
    }

    private function preparePackageDirectory(string $packageDir): void
    {
        $blobDir = $packageDir . DIRECTORY_SEPARATOR . 'blobs';
        if (file_exists($packageDir)) {
            if (is_link($packageDir) || !is_dir($packageDir)) throw new RuntimeException('Package destination is invalid.');
            $entries = scandir($packageDir);
            if ($entries === false) throw new RuntimeException('Package destination cannot be inspected.');
            $visible = array_values(array_diff($entries, ['.', '..']));
            if ($visible !== [] && $visible !== ['blobs']) throw new RuntimeException('Package directory must be empty.');
            if (is_link($blobDir)) throw new RuntimeException('Package blob directory is invalid.');
            if (is_dir($blobDir)) {
                $blobEntries = scandir($blobDir);
                if ($blobEntries === false || count(array_diff($blobEntries, ['.', '..'])) !== 0) throw new RuntimeException('Package blob directory must be empty.');
            } elseif (file_exists($blobDir) || !mkdir($blobDir, 0700, true)) {
                throw new RuntimeException('Unable to initialize package directory.');
            }
        } elseif (!mkdir($blobDir, 0700, true)) {
            throw new RuntimeException('Unable to initialize package directory.');
        }
        @chmod($packageDir, 0700);
        @chmod($blobDir, 0700);
    }

    private function writeJson(string $path, array $data): void
    {
        $this->writeBytes($path, CanonicalJson::encode($data));
    }

    private function writeBytes(string $path, string $contents): void
    {
        $tmp = $path . '.partial.' . bin2hex(random_bytes(12));
        $bytes = file_put_contents($tmp, $contents, LOCK_EX);
        if ($bytes === false || $bytes !== strlen($contents) || !rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException('Unable to write package data.');
        }
        @chmod($path, 0600);
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) return;
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($path);
    }
}
