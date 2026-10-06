<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

final class PackageVerifier
{
    public function assertPackageDirectory(string $packageDir): array
    {
        $root = realpath($packageDir);
        if ($root === false || !is_dir($root)) throw new RuntimeException('Unable to open package.');
        $headerPath = $root . DIRECTORY_SEPARATOR . 'header.json';
        $manifestPath = $root . DIRECTORY_SEPARATOR . 'manifest.enc';
        $blobDir = $root . DIRECTORY_SEPARATOR . 'blobs';
        if (!is_file($headerPath) || !is_file($manifestPath) || !is_dir($blobDir)) throw new RuntimeException('Unable to open package.');
        $headerRaw = file_get_contents($headerPath);
        if ($headerRaw === false || strlen($headerRaw) > 65536) throw new RuntimeException('Unable to open package.');
        $header = json_decode($headerRaw, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($header) || ($header['format'] ?? null) !== 'SECURE-PKG-V4' || (int) ($header['version'] ?? 0) !== 4) throw new RuntimeException('Unable to open package.');
        if (!preg_match('/^[a-f0-9]{48}$/', (string) ($header['package_id'] ?? ''))) throw new RuntimeException('Unable to open package.');
        if (!is_string($header['salt'] ?? null) || !is_array($header['kdf'] ?? null)) throw new RuntimeException('Unable to open package.');
        $rootEntries = scandir($root);
        if ($rootEntries === false) throw new RuntimeException('Unable to open package.');
        foreach ($rootEntries as $entry) {
            if (in_array($entry, ['.', '..', 'header.json', 'manifest.enc', 'blobs'], true)) continue;
            throw new RuntimeException('Unable to open package.');
        }
        $entries = scandir($blobDir);
        if ($entries === false || count($entries) - 2 > 100000) throw new RuntimeException('Unable to open package.');
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            if (!preg_match('/^[a-f0-9]{48}\.bin$/', $entry)) throw new RuntimeException('Unable to open package.');
            $path = $blobDir . DIRECTORY_SEPARATOR . $entry;
            if (!is_file($path) || is_link($path)) throw new RuntimeException('Unable to open package.');
        }
        $manifestSize = filesize($manifestPath);
        if ($manifestSize === false || $manifestSize > 128 * 1024 * 1024) throw new RuntimeException('Unable to open package.');
        return $header;
    }
}
