<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Crypto\CryptoEngine;
use SecurePackage\Crypto\KeyDerivation;
use SecurePackage\Security\Validator;

final class PackageReader
{
    public function restore(string $packageDir, string $destinationDir, string $password, string $pattern): array
    {
        $header = (new PackageVerifier())->assertPackageDirectory($packageDir);
        $headerPath = $packageDir . DIRECTORY_SEPARATOR . 'header.json';
        $manifestPath = $packageDir . DIRECTORY_SEPARATOR . 'manifest.enc';
        if (!is_file($headerPath) || !is_file($manifestPath)) {
            throw new RuntimeException('Unable to open package.');
        }

        $header = json_decode((string) file_get_contents($headerPath), true, 64, JSON_THROW_ON_ERROR);
        if (($header['format'] ?? null) !== 'SECURE-PKG-V6' || (int) ($header['version'] ?? 0) !== 6 || !preg_match('/^[a-f0-9]{48}$/', (string) ($header['package_id'] ?? ''))) {
            throw new RuntimeException('Unable to open package.');
        }
        $salt = base64_decode((string) ($header['salt'] ?? ''), true);
        if ($salt === false || strlen($salt) !== KeyDerivation::SALT_BYTES) {
            throw new RuntimeException('Unable to open package.');
        }

        Validator::validatePassword($password);
        Validator::validatePattern($pattern);
        $master = KeyDerivation::deriveMasterKey($password, $pattern, $salt, (int) ($header['kdf']['ops'] ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE), (int) ($header['kdf']['mem'] ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE));
        $manifestKey = KeyDerivation::deriveSubkey($master, 'manifest', $salt);
        $filenameKey = KeyDerivation::deriveSubkey($master, 'filename', $salt);
        $fileKeyRoot = KeyDerivation::deriveSubkey($master, 'files', $salt);

        $created = false;
        $paths = [];
        $seenIds = [];
        $seenPaths = [];
        $referencedBlobs = [];
        try {
            $manifestJson = CryptoEngine::decryptString((string) file_get_contents($manifestPath), $manifestKey, 'manifest|6');
            $manifest = json_decode($manifestJson, true, 64, JSON_THROW_ON_ERROR);
            if (($manifest['version'] ?? null) !== 6 || ($manifest['format'] ?? null) !== 'SECURE-PKG-V6' || ($manifest['schema'] ?? null) !== 2 || !isset($manifest['nodes']) || !is_array($manifest['nodes'])) {
                throw new RuntimeException('Unable to open package.');
            }
            if (count($manifest['nodes']) > 100000 || (int) ($manifest['node_count'] ?? -1) !== count($manifest['nodes'])) {
                throw new RuntimeException('Package manifest exceeds limits.');
            }

            if (file_exists($destinationDir)) {
                throw new RuntimeException('Destination directory already exists.');
            }
            if (!mkdir($destinationDir, 0700, true)) {
                throw new RuntimeException('Unable to create destination directory.');
            }
            $created = true;

            foreach ($manifest['nodes'] as $node) {
                $id = (string) ($node['id'] ?? '');
                $type = (string) ($node['type'] ?? '');
                $parent = $node['parent'] ?? null;
                $encodedName = (string) ($node['name'] ?? '');
                if ($id === '' || isset($seenIds[$id]) || $encodedName === '' || !in_array($type, ['dir', 'file'], true)) {
                    throw new RuntimeException('Unable to open package.');
                }
                $seenIds[$id] = true;

                $namePacked = base64_decode($encodedName, true);
                if ($namePacked === false) {
                    throw new RuntimeException('Unable to open package.');
                }
                $name = CryptoEngine::decryptString($namePacked, $filenameKey, 'name|' . $id);
                $this->validateRestoredName($name);

                $parentPath = $parent === null ? $destinationDir : ($paths[(string) $parent] ?? null);
                if ($parentPath === null) {
                    throw new RuntimeException('Unable to open package.');
                }
                $target = $parentPath . DIRECTORY_SEPARATOR . $name;
                $canonicalKey = $this->normalizedTarget($target);
                if (isset($seenPaths[$canonicalKey]) || file_exists($target)) {
                    throw new RuntimeException('Unable to open package.');
                }
                $seenPaths[$canonicalKey] = true;

                if ($type === 'dir') {
                    if (!mkdir($target, 0700) && !is_dir($target)) {
                        throw new RuntimeException('Unable to open package.');
                    }
                    $paths[$id] = $target;
                    continue;
                }

                $blob = (string) ($node['blob'] ?? '');
                if (!preg_match('/^[a-f0-9]{48}\.bin$/', $blob)) {
                    throw new RuntimeException('Unable to open package.');
                }
                $referencedBlobs[$blob] = true;
                $blobPath = $packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blob;
                if (!is_file($blobPath)) {
                    throw new RuntimeException('Unable to open package.');
                }
                $fileKey = KeyDerivation::deriveFileKey($fileKeyRoot, $id);
                CryptoEngine::decryptFile($blobPath, $target, $fileKey, 'file|' . $id . '|v6', (int) ($node['size'] ?? -1));
                sodium_memzero($fileKey);
                $paths[$id] = $target;
            }

            $blobEntries = array_values(array_filter(scandir($packageDir . DIRECTORY_SEPARATOR . 'blobs') ?: [], static fn(string $entry): bool => $entry !== '.' && $entry !== '..'));
            sort($blobEntries);
            $referenced = array_keys($referencedBlobs);
            sort($referenced);
            if ($blobEntries !== $referenced) {
                throw new RuntimeException('Unable to open package.');
            }

            return ['nodes' => count($manifest['nodes']), 'files' => count($referencedBlobs)];
        } catch (\Throwable $e) {
            if ($created) {
                $this->removeDirectory($destinationDir);
            }
            throw new RuntimeException('Unable to open package.', 0, $e);
        } finally {
            sodium_memzero($master);
            sodium_memzero($manifestKey);
            sodium_memzero($filenameKey);
            sodium_memzero($fileKeyRoot);
        }
    }

    private function validateRestoredName(string $name): void
    {
        if ($name === '' || $name === '.' || $name === '..' || str_contains($name, "\0") || str_contains($name, '/') || str_contains($name, '\\')) {
            throw new RuntimeException('Unable to open package.');
        }
        if (preg_match('/^[. ]+$/u', $name) === 1) {
            throw new RuntimeException('Unable to open package.');
        }
        if (preg_match('/[\x00-\x1F\x7F:\/]/u', $name) === 1) {
            throw new RuntimeException('Unable to open package.');
        }
        if (str_ends_with($name, ' ') || str_ends_with($name, '.')) {
            throw new RuntimeException('Unable to open package.');
        }
        $device = strtoupper($name);
        if (preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i', $device) === 1) {
            throw new RuntimeException('Unable to open package.');
        }
        if (preg_match('/^[.]+$/u', $name) === 1) {
            throw new RuntimeException('Unable to open package.');
        }
    }

    private function normalizedTarget(string $target): string
    {
        $parent = dirname($target);
        $name = basename($target);
        return rtrim(str_replace('\\', '/', $parent), '/') . '/' . strtolower($name);
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
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
