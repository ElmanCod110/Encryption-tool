<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SecurePackage\Crypto\CryptoEngine;
use SecurePackage\Crypto\KeyDerivation;

final class PackageBuilder
{
    public function build(string $sourceDir, string $packageDir, string $password, string $pattern, ?string $packageId = null): array
    {
        $sourceDir = $this->canonicalDirectory($sourceDir);
        $packageId ??= PackageId::generate();
        PackageId::assert($packageId);
        $this->preparePackageDirectory($packageDir);

        $salt = random_bytes(KeyDerivation::SALT_BYTES);
        $master = KeyDerivation::deriveMasterKey($password, $pattern, $salt);
        $manifestKey = KeyDerivation::deriveSubkey($master, 'manifest', $salt);
        $filenameKey = KeyDerivation::deriveSubkey($master, 'filename', $salt);
        $fileKeyRoot = KeyDerivation::deriveSubkey($master, 'files', $salt);
        $manifest = new ManifestBuilder();
        $dirMap = ['' => null];
        $usedNames = [];

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($sourceDir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $entry) {
                if ($entry->isLink() || $entry->isDir() && $entry->isLink()) {
                    throw new RuntimeException('Symbolic links are not supported.');
                }
                if (!$entry->isDir() && !$entry->isFile()) {
                    throw new RuntimeException('Unsupported filesystem entry encountered.');
                }

                $relative = $this->relativePath($sourceDir, $entry->getPathname());
                $parentRelative = dirname($relative);
                $parentRelative = $parentRelative === '.' ? '' : str_replace('\\', '/', $parentRelative);
                $parentId = $dirMap[$parentRelative] ?? null;
                if ($parentRelative !== '' && $parentId === null) {
                    throw new RuntimeException('Manifest parent order is invalid.');
                }

                $name = basename($relative);
                $nameKey = ($parentId ?? 'root') . "\0" . $name;
                if (isset($usedNames[$nameKey])) {
                    throw new RuntimeException('Duplicate directory entry detected.');
                }
                $usedNames[$nameKey] = true;

                $id = bin2hex(random_bytes(16));
                $encryptedName = base64_encode(CryptoEngine::encryptString($name, $filenameKey, 'name|' . $id));

                if ($entry->isDir()) {
                    $dirMap[$relative] = $id;
                    $manifest->addDirectory($id, $parentId, $encryptedName);
                    continue;
                }

                $blobId = bin2hex(random_bytes(24)) . '.bin';
                $fileKey = KeyDerivation::deriveFileKey($fileKeyRoot, $id);
                $destination = $packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blobId;
                CryptoEngine::encryptFile($entry->getPathname(), $destination, $fileKey, 'file|' . $id . '|v3', (int) $entry->getSize());
                $manifest->addFile($id, $parentId, $encryptedName, $blobId, (int) $entry->getSize());
                sodium_memzero($fileKey);
            }

            $manifestPayload = CryptoEngine::encryptString($manifest->toJson(), $manifestKey, 'manifest|3');
            $this->writeAtomic($packageDir . DIRECTORY_SEPARATOR . 'manifest.enc', $manifestPayload);

            $header = [
                'format' => 'SECURE-PKG-V3',
                'version' => 3,
                'package_id' => $packageId,
                'kdf' => [
                    'name' => 'argon2id',
                    'salt_bytes' => KeyDerivation::SALT_BYTES,
                    'ops' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                    'mem' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
                ],
                'payload' => [
                    'small' => 'xchacha20poly1305-ietf',
                    'stream' => 'secretstream-xchacha20poly1305',
                ],
                'salt' => base64_encode($salt),
            ];
            $this->writeAtomic(
                $packageDir . DIRECTORY_SEPARATOR . 'header.json',
                json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
            );

            return [
                'format' => 'SECURE-PKG-V3',
                'package_id' => $packageId,
                'nodes' => $manifest->count(),
                'salt' => base64_encode($salt),
            ];
        } catch (\Throwable $e) {
            $this->removeDirectory($packageDir);
            throw $e;
        } finally {
            sodium_memzero($master);
            sodium_memzero($manifestKey);
            sodium_memzero($filenameKey);
            sodium_memzero($fileKeyRoot);
        }
    }

    private function canonicalDirectory(string $path): string
    {
        $real = realpath($path);
        if ($real === false || !is_dir($real)) {
            throw new RuntimeException('Source directory does not exist.');
        }
        return rtrim($real, DIRECTORY_SEPARATOR);
    }

    private function relativePath(string $base, string $path): string
    {
        $base = rtrim(str_replace('\\', '/', $base), '/') . '/';
        $path = str_replace('\\', '/', realpath($path) ?: $path);
        if (!str_starts_with($path, $base)) {
            throw new RuntimeException('Filesystem entry escaped the source directory.');
        }
        $relative = ltrim(substr($path, strlen($base)), '/');
        if ($relative === '' || str_contains($relative, "\0")) {
            throw new RuntimeException('Invalid relative path.');
        }
        return $relative;
    }

    private function preparePackageDirectory(string $packageDir): void
    {
        if (file_exists($packageDir)) {
            if (!is_dir($packageDir)) {
                throw new RuntimeException('Package destination is invalid.');
            }
            $entries = scandir($packageDir);
            if ($entries === false || count(array_diff($entries, ['.', '..'])) !== 0) {
                throw new RuntimeException('Package directory must be empty.');
            }
        } elseif (!mkdir($packageDir, 0700, true)) {
            throw new RuntimeException('Unable to initialize package directory.');
        }
        if (!mkdir($packageDir . DIRECTORY_SEPARATOR . 'blobs', 0700, true)) {
            throw new RuntimeException('Unable to initialize package directory.');
        }
    }

    private function writeAtomic(string $path, string $contents): void
    {
        $temp = $path . '.partial.' . bin2hex(random_bytes(8));
        if (file_put_contents($temp, $contents, LOCK_EX) === false || !rename($temp, $path)) {
            @unlink($temp);
            throw new RuntimeException('Unable to write package metadata.');
        }
        @chmod($path, 0600);
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir() && !$item->isLink()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }
        @rmdir($path);
    }
}
