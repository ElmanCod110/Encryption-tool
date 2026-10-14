<?php
declare(strict_types=1);

namespace SecurePackage\Project;


final class V14PackageVerifier
{
    public function assertPackageDirectory(string $packageDir): array
    {
        $root = realpath($packageDir);
        if ($root === false || !is_dir($root) || is_link($packageDir)) throw new PackageRestoreRejectedException('Unable to open package.');
        $headerPath = $root . DIRECTORY_SEPARATOR . 'header.json';
        $manifestPath = $root . DIRECTORY_SEPARATOR . 'manifest.enc';
        $completePath = $root . DIRECTORY_SEPARATOR . 'complete.json';
        $blobDir = $root . DIRECTORY_SEPARATOR . 'blobs';
        if (!is_file($headerPath) || is_link($headerPath) || !is_file($manifestPath) || is_link($manifestPath) || !is_file($completePath) || is_link($completePath) || !is_dir($blobDir) || is_link($blobDir)) throw new PackageRestoreRejectedException('Unable to open package.');
        $completeSize = filesize($completePath);
        if ($completeSize === false) throw new PackageStorageException('Unable to inspect package completion record.');
        if ($completeSize > 4096) throw new PackageRestoreRejectedException('Unable to open package.');
        $headerRaw = file_get_contents($headerPath);
        if ($headerRaw === false) throw new PackageStorageException('Unable to read package header.');
        if (strlen($headerRaw) > V14Descriptor::MAX_HEADER_BYTES) throw new PackageRestoreRejectedException('Unable to open package.');
        try { $header = json_decode($headerRaw, true, 32, JSON_THROW_ON_ERROR); } catch (\JsonException) { throw new PackageRestoreRejectedException('Unable to open package.'); }
        if (!is_array($header)) throw new PackageRestoreRejectedException('Unable to open package.');
        try {
            V14Descriptor::assertHeader($header);
        } catch (\RuntimeException|\InvalidArgumentException $exception) {
            throw new PackageRestoreRejectedException('Unable to open package.', 0, $exception);
        }
        $manifestSize = filesize($manifestPath);
        if ($manifestSize === false) throw new PackageStorageException('Unable to inspect encrypted manifest.');
        if ($manifestSize < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES || $manifestSize > V14Descriptor::MAX_MANIFEST_BYTES + 64) throw new PackageRestoreRejectedException('Unable to open package.');
        $entries = scandir($root);
        if ($entries === false) throw new PackageStorageException('Unable to inventory package directory.');
        foreach ($entries as $entry) {
            if (in_array($entry, ['.', '..', 'header.json', 'manifest.enc', 'complete.json', 'blobs'], true)) continue;
            throw new PackageRestoreRejectedException('Unable to open package.');
        }
        $blobEntries = scandir($blobDir);
        if ($blobEntries === false) throw new PackageStorageException('Unable to inventory package blobs.');
        if (count($blobEntries) - 2 > V14Descriptor::MAX_BLOBS) throw new PackageRestoreRejectedException('Unable to open package.');
        $totalCipher = 0;
        foreach ($blobEntries as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            if (!preg_match('/^[a-f0-9]{48}\.bin$/', $entry)) throw new PackageRestoreRejectedException('Unable to open package.');
            $path = $blobDir . DIRECTORY_SEPARATOR . $entry;
            if (is_link($path) || !is_file($path)) throw new PackageRestoreRejectedException('Unable to open package.');
            $size = filesize($path);
            if ($size === false) throw new PackageStorageException('Unable to inspect package blob.');
            if ($size < 1 || $size > V14Descriptor::MAX_FILE_BYTES + 64 * 1024 * 1024) throw new PackageRestoreRejectedException('Unable to open package.');
            $totalCipher += $size;
            if ($totalCipher > V14Descriptor::MAX_TOTAL_PLAIN_BYTES + 64 * 1024 * 1024) throw new PackageRestoreRejectedException('Unable to open package.');
        }
        return $header;
    }
}
