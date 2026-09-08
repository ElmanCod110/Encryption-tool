<?php
declare(strict_types=1);

namespace TCH\Project;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;
use RuntimeException;
use TCH\Crypto\CryptoEngine;
use TCH\Crypto\KeyDerivation;

final class PackageBuilder
{
    public function build(string $sourceDir, string $packageDir, string $password, string $pattern): array
    {
        $salt = random_bytes(KeyDerivation::SALT_BYTES);
        $master = KeyDerivation::deriveMasterKey($password, $pattern, $salt);
        $manifestKey = KeyDerivation::deriveSubkey($master, 'manifest', $salt);
        $filenameKey = KeyDerivation::deriveSubkey($master, 'filename', $salt);
        $fileKeyRoot = KeyDerivation::deriveSubkey($master, 'files', $salt);
        $manifest = new ManifestBuilder();
        $inodeMap = ['' => null];
        $dirMap = ['' => null];

        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $file) {
            $relative = $this->relativePath($sourceDir, $file->getPathname());
            $relative = str_replace('\\', '/', $relative);
            $parentRelative = dirname($relative);
            $parentRelative = $parentRelative === '.' ? '' : $parentRelative;
            $parentId = $dirMap[$parentRelative] ?? null;
            if ($file->isDir()) {
                $id = bin2hex(random_bytes(16));
                $dirMap[$relative] = $id;
                $name = basename($relative);
                $encryptedName = base64_encode(CryptoEngine::encryptString($name, $filenameKey, 'name|' . $id));
                $manifest->addDirectory($id, $parentId, $encryptedName);
                continue;
            }
            if (!$file->isFile()) {
                throw new RuntimeException('Unsupported filesystem entry encountered.');
            }
            $id = bin2hex(random_bytes(16));
            $blobId = bin2hex(random_bytes(20));
            $name = basename($relative);
            $encryptedName = base64_encode(CryptoEngine::encryptString($name, $filenameKey, 'name|' . $id));
            $fileKey = KeyDerivation::deriveSubkey($fileKeyRoot, 'file', $id);
            $destination = $packageDir . DIRECTORY_SEPARATOR . 'blobs' . DIRECTORY_SEPARATOR . $blobId . '.bin';
            CryptoEngine::encryptFile($file->getPathname(), $destination, $fileKey, 'file|' . $id);
            $manifest->addFile($id, $parentId, $encryptedName, $blobId . '.bin', $file->getSize());
        }

        $manifestPayload = CryptoEngine::encryptString($manifest->toJson(), $manifestKey, 'manifest|1');
        file_put_contents($packageDir . DIRECTORY_SEPARATOR . 'manifest.enc', $manifestPayload, LOCK_EX);
        $header = [
            'format' => 'TCH-PKG-V1',
            'kdf' => 'argon2id',
            'cipher' => 'xchacha20poly1305',
            'stream_cipher' => 'secretstream-xchacha20poly1305',
            'salt' => base64_encode($salt),
        ];
        file_put_contents($packageDir . DIRECTORY_SEPARATOR . 'header.bin', json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), LOCK_EX);
        return ['salt' => base64_encode($salt), 'files' => count($manifest->toJson())];
    }

    private function relativePath(string $base, string $path): string
    {
        $base = rtrim(str_replace('\\', '/', realpath($base) ?: $base), '/') . '/';
        $path = str_replace('\\', '/', realpath($path) ?: $path);
        return ltrim(str_replace($base, '', $path), '/');
    }
}
