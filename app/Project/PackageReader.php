<?php
declare(strict_types=1);

namespace TCH\Project;

use RuntimeException;
use TCH\Crypto\CryptoEngine;
use TCH\Crypto\KeyDerivation;

final class PackageReader
{
    public function restore(string $packageDir, string $destinationDir, string $password, string $pattern): void
    {
        $headerPath = $packageDir . DIRECTORY_SEPARATOR . 'header.bin';
        $manifestPath = $packageDir . DIRECTORY_SEPARATOR . 'manifest.enc';
        if (!is_file($headerPath) || !is_file($manifestPath)) {
            throw new RuntimeException('Invalid package.');
        }
        $header = json_decode((string) file_get_contents($headerPath), true, 32, JSON_THROW_ON_ERROR);
        if (($header['format'] ?? null) !== 'TCH-PKG-V1' || ($header['kdf'] ?? null) !== 'argon2id') {
            throw new RuntimeException('Unsupported package format.');
        }
        $salt = base64_decode((string) ($header['salt'] ?? ''), true);
        if ($salt === false || strlen($salt) !== KeyDerivation::SALT_BYTES) {
            throw new RuntimeException('Invalid package salt.');
        }
        $master = KeyDerivation::deriveMasterKey($password, $pattern, $salt);
        $manifestKey = KeyDerivation::deriveSubkey($master, 'manifest', $salt);
        $filenameKey = KeyDerivation::deriveSubkey($master, 'filename', $salt);
        $fileKeyRoot = KeyDerivation::deriveSubkey($master, 'files', $salt);

        $manifestJson = CryptoEngine::decryptString((string) file_get_contents($manifestPath), $manifestKey, 'manifest|1');
        $manifest = json_decode($manifestJson, true, 32, JSON_THROW_ON_ERROR);
        if (!isset($manifest['nodes']) || !is_array($manifest['nodes'])) {
            throw new RuntimeException('Invalid manifest.');
        }
        if (!is_dir($destinationDir) && !mkdir($destinationDir, 0700, true) && !is_dir($destinationDir)) {
            throw new RuntimeException('Unable to create destination directory.');
        }
        $paths = [];
        foreach ($manifest['nodes'] as $node) {
            $id = (string) ($node['id'] ?? '');
            $parent = $node['parent'] ?? null;
            $nameEncoded = (string) ($node['name'] ?? '');
            if ($id === '' || $nameEncoded === '') {
                throw new RuntimeException('Invalid manifest node.');
            }
            $namePacked = base64_decode($nameEncoded, true);
            if ($namePacked === false) {
                throw new RuntimeException('Invalid encrypted name.');
            }
            $name = CryptoEngine::decryptString($namePacked, $filenameKey, 'name|' . $id);
            $parentPath = $parent === null ? $destinationDir : ($paths[(string) $parent] ?? null);
            if ($parentPath === null) {
                throw new RuntimeException('Invalid manifest parent reference.');
            }
            $target = $parentPath . DIRECTORY_SEPARATOR . $name;
            if ($node['type'] === 'dir') {
                if (!mkdir($target, 0700, true) && !is_dir($target)) {
                    throw new RuntimeException('Unable to recreate directory.');
                }
                $paths[$id] = $target;
            } elseif ($node['type'] === 'file') {
                $blob = basename((string) ($node['blob'] ?? ''));
                if ($blob === '' || !is_file($packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blob)) {
                    throw new RuntimeException('Missing encrypted file blob.');
                }
                $fileKey = KeyDerivation::deriveSubkey($fileKeyRoot, 'file', $id);
                CryptoEngine::decryptFile($packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blob, $target, $fileKey, 'file|' . $id);
                $paths[$id] = $target;
            } else {
                throw new RuntimeException('Unsupported manifest node type.');
            }
        }
    }
}
