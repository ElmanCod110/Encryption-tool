<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Security\Validator;
use Throwable;

/** Reads and restores the frozen, single-file binary package format. */
final class StablePackageReader
{
    public function restore(
        string $packageFile,
        string $destinationDir,
        string $password,
        string $pattern,
        ?string $recoveryKey = null
    ): array {
        StablePackageDescriptor::assertRuntime();
        $source = $this->canonicalPackageFile($packageFile);
        $destination = $this->canonicalDestinationDirectory($destinationDir);
        if (file_exists($destination) || is_link($destination)) {
            throw new RuntimeException('Restore destination already exists.');
        }
        $input = @fopen($source, 'rb');
        if ($input === false) {
            throw new RuntimeException('Unable to open package.');
        }

        $stage = null;
        $active = null;
        $rootKey = null;
        $manifestKey = null;
        $fileRootKey = null;
        $manifestPlain = null;
        $createdOutputRoot = false;
        $createdOutputRootIdentity = null;
        $createdDirectories = [];
        $createdFiles = [];

        try {
            $fileStat = fstat($input);
            if (!is_array($fileStat) || !isset($fileStat['size']) || (int) $fileStat['size'] < StablePackageDescriptor::HEADER_BYTES
                || (int) $fileStat['size'] > StablePackageDescriptor::MAX_PACKAGE_BYTES) {
                throw new RuntimeException('Package size is outside the supported bounds.');
            }
            $rawHeader = StablePackageDescriptor::readExact($input, StablePackageDescriptor::HEADER_BYTES);
            $header = StablePackageDescriptor::parseHeader($rawHeader);
            $rootKey = StablePackageCrypto::unwrapRootKey($header, $password, $pattern, $recoveryKey);
            $manifestKey = StablePackageCrypto::deriveSubkey($rootKey, 'MANIFEST', $header['package_id']);
            $fileRootKey = StablePackageCrypto::deriveSubkey($rootKey, 'FILE-ROOT', $header['package_id']);
            $stage = $this->createPrivateStage();

            $observedFiles = [];
            $observedOrder = [];
            $observedIds = [];
            $observedFileCount = 0;
            $declaredTotalBytes = 0;
            $actualTotalBytes = 0;
            $recordCount = 0;
            $manifestSeen = false;

            while (!$manifestSeen) {
                $recordHeader = fread($input, StablePackageDescriptor::RECORD_HEADER_BYTES);
                if ($recordHeader === false || $recordHeader === '') {
                    throw new RuntimeException('Package has no final manifest record.');
                }
                if (strlen($recordHeader) !== StablePackageDescriptor::RECORD_HEADER_BYTES) {
                    throw new RuntimeException('Package record header is truncated.');
                }
                $recordCount++;
                $maximumRecords = (2 * StablePackageDescriptor::MAX_NODES)
                    + intdiv(StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES, StablePackageDescriptor::CHUNK_BYTES) + 1;
                if ($recordCount > $maximumRecords) {
                    throw new RuntimeException('Package contains too many records.');
                }
                $type = ord($recordHeader[0]);
                $bodyLength = unpack('Nvalue', substr($recordHeader, 1, 4))['value'] ?? 0;
                $this->validateRecordLength((int) $type, (int) $bodyLength, $active !== null);

                if ($type === StablePackageDescriptor::RECORD_FILE_START) {
                    if ($active !== null || $observedFileCount >= StablePackageDescriptor::MAX_NODES) {
                        throw new RuntimeException('Package file stream ordering is invalid.');
                    }
                    $body = StablePackageDescriptor::readExact($input, (int) $bodyLength);
                    $fileId = substr($body, 0, StablePackageDescriptor::FILE_ID_BYTES);
                    $fileIdHex = bin2hex($fileId);
                    $size = StablePackageDescriptor::unpackUint64(substr($body, 16, 8));
                    $streamHeader = substr($body, 24, StablePackageDescriptor::STREAM_HEADER_BYTES);
                    if (StablePackageDescriptor::isZeroBytes($fileId) || isset($observedIds[$fileIdHex])
                        || $size > StablePackageDescriptor::MAX_FILE_BYTES) {
                        throw new RuntimeException('Package file header is invalid.');
                    }
                    $declaredTotalBytes += $size;
                    if ($declaredTotalBytes > StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES) {
                        throw new RuntimeException('Package exceeds the total data limit.');
                    }
                    $fileKey = StablePackageCrypto::deriveSubkey($fileRootKey, 'FILE', $header['package_id'], $fileIdHex);
                    $streamState = sodium_crypto_secretstream_xchacha20poly1305_init_pull($streamHeader, $fileKey);
                    $stagePath = $stage . DIRECTORY_SEPARATOR . $fileIdHex . '.plain';
                    $out = @fopen($stagePath, 'xb');
                    if ($out === false) {
                        sodium_memzero($fileKey);
                        throw new RuntimeException('Unable to stage decrypted file.');
                    }
                    @chmod($stagePath, 0600);
                    $observedIds[$fileIdHex] = true;
                    $observedOrder[] = $fileIdHex;
                    $active = [
                        'id' => $fileId,
                        'id_hex' => $fileIdHex,
                        'size' => $size,
                        'expected_chunks' => StablePackageDescriptor::expectedChunkCount($size),
                        'chunks' => 0,
                        'written' => 0,
                        'key' => $fileKey,
                        'state' => $streamState,
                        'out' => $out,
                        'stage_path' => $stagePath,
                    ];
                    continue;
                }

                if ($type === StablePackageDescriptor::RECORD_FILE_CHUNK) {
                    if ($active === null) {
                        throw new RuntimeException('Package chunk appears outside a file stream.');
                    }
                    $body = StablePackageDescriptor::readExact($input, (int) $bodyLength);
                    $recordFileId = substr($body, 0, StablePackageDescriptor::FILE_ID_BYTES);
                    $sequence = unpack('Nvalue', substr($body, 16, 4))['value'] ?? -1;
                    $cipher = substr($body, 20);
                    if (!hash_equals($active['id'], $recordFileId) || (int) $sequence !== $active['chunks']
                        || $active['chunks'] >= $active['expected_chunks']) {
                        throw new RuntimeException('Package chunk sequence is invalid.');
                    }
                    $plainResult = sodium_crypto_secretstream_xchacha20poly1305_pull(
                        $active['state'],
                        $cipher,
                        StablePackageCrypto::chunkAad($header['core_hash'], $header['package_id'], $active['id'],
                            (int) $sequence, $active['size'])
                    );
                    if ($plainResult === false) {
                        throw new RuntimeException('Package chunk authentication failed.');
                    }
                    [$plain, $tag] = $plainResult;
                    try {
                        $plainLength = strlen($plain);
                        $newTotal = $active['written'] + $plainLength;
                        if ($newTotal > $active['size']) {
                            throw new RuntimeException('Decrypted file exceeds its declared size.');
                        }
                        if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE) {
                            if ($plainLength !== StablePackageDescriptor::CHUNK_BYTES || $newTotal >= $active['size']
                                || ($active['chunks'] + 1) >= $active['expected_chunks']) {
                                throw new RuntimeException('Non-final file chunk has an invalid length or position.');
                            }
                        } elseif ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                            if ($newTotal !== $active['size']
                                || ($active['size'] === 0 && ($plainLength !== 0 || $active['chunks'] !== 0))
                                || ($active['size'] > 0 && $plainLength === 0)
                                || ($active['chunks'] + 1) !== $active['expected_chunks']) {
                                throw new RuntimeException('Final file chunk has an invalid length or position.');
                            }
                        } else {
                            throw new RuntimeException('Unsupported secretstream tag.');
                        }

                        if ($plainLength > 0) {
                            StablePackageDescriptor::writeAll($active['out'], $plain);
                        }
                        $active['written'] = $newTotal;
                        $active['chunks']++;
                    } finally {
                        if ($plain !== '') sodium_memzero($plain);
                    }

                    if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                        if (!fflush($active['out'])) {
                            throw new RuntimeException('Unable to flush staged file.');
                        }
                        if (function_exists('fsync') && !fsync($active['out'])) {
                            throw new RuntimeException('Unable to synchronize staged file.');
                        }
                        if (!fclose($active['out'])) {
                            $active['out'] = null;
                            throw new RuntimeException('Unable to close staged file.');
                        }
                        $observedFiles[$active['id_hex']] = [
                            'size' => $active['size'],
                            'chunks' => $active['chunks'],
                            'path' => $active['stage_path'],
                        ];
                        $observedFileCount++;
                        $actualTotalBytes += $active['written'];
                        if ($actualTotalBytes > StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES) {
                            throw new RuntimeException('Package exceeds the total data limit.');
                        }
                        sodium_memzero($active['key']);
                        if (is_string($active['state'])) sodium_memzero($active['state']);
                        $active = null;
                    }
                    continue;
                }

                if ($type === StablePackageDescriptor::RECORD_MANIFEST) {
                    if ($active !== null || $bodyLength < StablePackageDescriptor::NONCE_BYTES + StablePackageDescriptor::AEAD_TAG_BYTES) {
                        throw new RuntimeException('Manifest record is out of order or truncated.');
                    }
                    $body = StablePackageDescriptor::readExact($input, (int) $bodyLength);
                    $nonce = substr($body, 0, StablePackageDescriptor::NONCE_BYTES);
                    $cipher = substr($body, StablePackageDescriptor::NONCE_BYTES);
                    $manifestPlain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                        $cipher,
                        StablePackageCrypto::manifestAad($header['core_hash']),
                        $nonce,
                        $manifestKey
                    );
                    if (!is_string($manifestPlain)) {
                        throw new RuntimeException('Manifest authentication failed.');
                    }
                    $trailing = fread($input, 1);
                    if ($trailing === false || $trailing !== '') {
                        throw new RuntimeException('Package contains trailing data after the manifest.');
                    }
                    $manifestSeen = true;
                    continue;
                }

                throw new RuntimeException('Package contains an unknown record type.');
            }

            if (!is_string($manifestPlain)) {
                throw new RuntimeException('Package manifest is missing.');
            }
            $decodedManifest = StablePackageDescriptor::decodeManifest($manifestPlain);
            if ($decodedManifest['file_count'] !== $observedFileCount
                || $decodedManifest['total_plain_bytes'] !== $actualTotalBytes
                || count($observedFiles) !== $decodedManifest['file_count']) {
                throw new RuntimeException('Package manifest and file streams disagree.');
            }
            $expectedStreamOrder = [];
            foreach ($decodedManifest['entries'] as $entry) {
                if ($entry['type'] !== 2) {
                    continue;
                }
                $expectedStreamOrder[] = $entry['id_hex'];
                $observed = $observedFiles[$entry['id_hex']] ?? null;
                if (!is_array($observed) || $observed['size'] !== $entry['size'] || $observed['chunks'] !== $entry['chunks']) {
                    throw new RuntimeException('Package manifest references an absent or inconsistent file stream.');
                }
            }
            if ($observedOrder !== $expectedStreamOrder) {
                throw new RuntimeException('File streams are not in canonical manifest order.');
            }
            // File identifiers are unique in the manifest and the inventories have equal counts;
            // every manifest file was found above, so no unreferenced stream can remain.
            $this->extractValidatedFiles($decodedManifest['entries'], $observedFiles, $stage, $destination,
                $createdOutputRoot, $createdOutputRootIdentity, $createdDirectories, $createdFiles);
            $this->removePrivateStage($stage);
            $stage = null;

            return [
                'package_id' => $header['package_id_hex'],
                'files' => $decodedManifest['file_count'],
                'directories' => $decodedManifest['directory_count'],
                'nodes' => count($decodedManifest['entries']),
                'total_plain_bytes' => $decodedManifest['total_plain_bytes'],
            ];
        } catch (Throwable $e) {
            if (is_array($active)) {
                if (is_resource($active['out'] ?? null)) fclose($active['out']);
                if (is_string($active['key'] ?? null)) sodium_memzero($active['key']);
                if (is_string($active['state'] ?? null)) sodium_memzero($active['state']);
            }
            if ($createdOutputRoot) {
                try {
                    $this->rollbackOutput($createdFiles, $createdDirectories, $destination, $createdOutputRootIdentity);
                } catch (Throwable $cleanupError) {
                    throw new RuntimeException('Restore failed and created output could not be fully cleaned up.', 0, $cleanupError);
                }
            }
            throw new RuntimeException('Unable to open package.', 0, $e);
        } finally {
            if (is_resource($input)) fclose($input);
            if (is_array($active)) {
                if (is_resource($active['out'] ?? null)) fclose($active['out']);
                if (is_string($active['key'] ?? null)) sodium_memzero($active['key']);
                if (is_string($active['state'] ?? null)) sodium_memzero($active['state']);
            }
            if (is_string($rootKey)) sodium_memzero($rootKey);
            if (is_string($manifestKey)) sodium_memzero($manifestKey);
            if (is_string($fileRootKey)) sodium_memzero($fileRootKey);
            if (is_string($manifestPlain)) sodium_memzero($manifestPlain);
            $password = '';
            $pattern = '';
            if (is_string($stage) && is_dir($stage)) {
                $this->removePrivateStage($stage);
            }
        }
    }

    private function validateRecordLength(int $type, int $length, bool $hasActiveFile): void
    {
        if ($length < 1 || $length > 0xFFFFFFFF) {
            throw new RuntimeException('Package record length is invalid.');
        }
        if ($type === StablePackageDescriptor::RECORD_FILE_START) {
            if ($hasActiveFile || $length !== 48) {
                throw new RuntimeException('Package file-start record is invalid.');
            }
            return;
        }
        if ($type === StablePackageDescriptor::RECORD_FILE_CHUNK) {
            if (!$hasActiveFile || $length < StablePackageDescriptor::FILE_ID_BYTES + 4 + 17
                || $length > StablePackageDescriptor::MAX_FILE_CHUNK_RECORD_BYTES) {
                throw new RuntimeException('Package file-chunk record is invalid.');
            }
            return;
        }
        if ($type === StablePackageDescriptor::RECORD_MANIFEST) {
            if ($hasActiveFile || $length < StablePackageDescriptor::NONCE_BYTES + StablePackageDescriptor::AEAD_TAG_BYTES
                || $length > StablePackageDescriptor::MAX_MANIFEST_RECORD_BYTES) {
                throw new RuntimeException('Package manifest record is invalid.');
            }
            return;
        }
        throw new RuntimeException('Package contains an unsupported record type.');
    }

    private function extractValidatedFiles(array $entries, array $observedFiles, string $stage, string $destination,
        bool &$createdRoot, ?array &$createdRootIdentity, array &$createdDirectories, array &$createdFiles): void
    {
        $filesById = [];
        foreach ($observedFiles as $idHex => $observed) {
            $path = $observed['path'] ?? null;
            if (!is_string($idHex) || !preg_match('/^[a-f0-9]{32}$/D', $idHex)
                || !is_string($path) || is_link($path) || !is_file($path)
                || dirname($path) !== $stage || basename($path) !== $idHex . '.plain') {
                throw new RuntimeException('Private staging inventory is invalid.');
            }
            $filesById[$idHex] = $path;
        }
        if (count($filesById) !== count(array_filter($entries, static fn(array $entry): bool => $entry['type'] === 2))) {
            throw new RuntimeException('Private staging inventory does not match the manifest.');
        }

        if (file_exists($destination) || is_link($destination)) {
            throw new RuntimeException('Restore destination already exists.');
        }
        if (!@mkdir($destination, 0700)) {
            throw new RuntimeException('Unable to create restore destination.');
        }
        $createdRoot = true;
        $createdRootIdentity = $this->captureIdentity($destination);
        @chmod($destination, 0700);

        $directories = array_values(array_filter($entries, static fn(array $entry): bool => $entry['type'] === 1));
        usort($directories, static fn(array $a, array $b): int => ($a['depth'] <=> $b['depth']) ?: strcmp($a['path'], $b['path']));
        foreach ($directories as $entry) {
            $target = $destination . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entry['path']);
            if (file_exists($target) || is_link($target) || !@mkdir($target, 0700)) {
                throw new RuntimeException('Unable to create restored directory.');
            }
            $createdDirectories[] = ['path' => $target, 'identity' => $this->captureIdentity($target)];
            @chmod($target, 0700);
        }

        $files = array_values(array_filter($entries, static fn(array $entry): bool => $entry['type'] === 2));
        usort($files, static fn(array $a, array $b): int => strcmp($a['path'], $b['path']));
        foreach ($files as $entry) {
            $target = $destination . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entry['path']);
            $parent = dirname($target);
            if (!is_dir($parent) || is_link($parent) || file_exists($target) || is_link($target)) {
                throw new RuntimeException('Restored file destination is unsafe.');
            }
            $source = $filesById[$entry['id_hex']] ?? null;
            if (!is_string($source) || is_link($source) || !is_file($source)) {
                throw new RuntimeException('Authenticated file staging data is missing.');
            }
            $in = @fopen($source, 'rb');
            $out = @fopen($target, 'xb');
            if ($in === false || $out === false) {
                if (is_resource($in)) fclose($in);
                if (is_resource($out)) fclose($out);
                // Never unlink $target here: fopen('xb') did not establish ownership if it failed.
                throw new RuntimeException('Unable to create restored file without overwriting.');
            }
            $createdFiles[] = ['path' => $target, 'identity' => $this->captureIdentity($target)];
            @chmod($target, 0600);
            try {
                $copied = stream_copy_to_stream($in, $out);
                if (!is_int($copied) || $copied !== $entry['size']) {
                    throw new RuntimeException('Restored file copy was incomplete.');
                }
                if (!fflush($out) || (function_exists('fsync') && !fsync($out))) {
                    throw new RuntimeException('Unable to synchronize restored file.');
                }
            } finally {
                fclose($in);
                fclose($out);
            }
            // file_exists() is checked before creation; clear PHP's negative stat cache
            // before verifying the newly written output, especially for empty files.
            clearstatcache(true, $target);
            $actualSize = filesize($target);
            if ($actualSize === false || (int) $actualSize !== $entry['size']) {
                throw new RuntimeException('Restored file size does not match the authenticated manifest.');
            }
        }
    }

    private function canonicalPackageFile(string $path): string
    {
        if (is_link($path)) {
            throw new RuntimeException('Package file must not be a symbolic link.');
        }
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            throw new RuntimeException('Package file does not exist.');
        }
        return $real;
    }

    private function canonicalDestinationDirectory(string $path): string
    {
        $parent = realpath(dirname($path));
        $name = basename($path);
        if ($parent === false || !is_dir($parent) || $name === '' || $name === '.' || $name === '..') {
            throw new RuntimeException('Restore destination parent is invalid.');
        }
        return rtrim($parent, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
    }

    private function createPrivateStage(): string
    {
        $base = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $path = $base . DIRECTORY_SEPARATOR . 'spkg-stage-' . bin2hex(random_bytes(16));
            if (@mkdir($path, 0700)) {
                @chmod($path, 0700);
                if (is_link($path) || !is_dir($path)) {
                    @rmdir($path);
                    continue;
                }
                return $path;
            }
        }
        throw new RuntimeException('Unable to create private staging directory.');
    }

    private function removePrivateStage(string $root): void
    {
        if (is_link($root)) {
            if (!@unlink($root)) throw new RuntimeException('Unable to remove private staging link.');
            return;
        }
        if (!is_dir($root)) {
            return;
        }
        $entries = @scandir($root);
        if ($entries === false) {
            throw new RuntimeException('Unable to inspect private staging directory for cleanup.');
        }
        foreach (array_diff($entries, ['.', '..']) as $name) {
            $path = $root . DIRECTORY_SEPARATOR . $name;
            if (is_link($path) || is_file($path)) {
                if (!@unlink($path)) throw new RuntimeException('Unable to remove private staged file.');
            } elseif (is_dir($path)) {
                $this->removePrivateStage($path);
            } elseif (file_exists($path)) {
                if (!@unlink($path)) throw new RuntimeException('Unable to remove private staged entry.');
            }
        }
        if (!@rmdir($root)) {
            throw new RuntimeException('Unable to remove private staging directory.');
        }
    }

    private function rollbackOutput(array $files, array $directories, string $root, ?array $rootIdentity): void
    {
        $failures = [];
        foreach (array_reverse($files) as $owned) {
            $path = $owned['path'] ?? '';
            if (!is_string($path) || (!file_exists($path) && !is_link($path))) continue;
            if (!$this->matchesIdentity($path, $owned['identity'] ?? null) || is_link($path) || !is_file($path)) {
                $failures[] = $path;
                continue;
            }
            if (!@unlink($path)) $failures[] = $path;
        }
        foreach (array_reverse($directories) as $owned) {
            $path = $owned['path'] ?? '';
            if (!is_string($path) || (!file_exists($path) && !is_link($path))) continue;
            if (!$this->matchesIdentity($path, $owned['identity'] ?? null) || is_link($path) || !is_dir($path)) {
                $failures[] = $path;
                continue;
            }
            if (!@rmdir($path)) $failures[] = $path;
        }
        if (!file_exists($root) && !is_link($root)) {
            // The root was removed by another actor; do not recreate or touch it.
        } elseif (!$this->matchesIdentity($root, $rootIdentity) || is_link($root) || !is_dir($root)) {
            $failures[] = $root;
        } elseif (!@rmdir($root)) {
            // Unknown entries are preserved; never recursively delete data not created here.
            $failures[] = $root;
        }
        if ($failures !== []) {
            throw new RuntimeException('Output rollback could not safely remove every path created by this restore.');
        }
    }

    private function captureIdentity(string $path): ?array
    {
        $stat = @lstat($path);
        if (!is_array($stat)) return null;
        return ['dev' => (int) ($stat['dev'] ?? -1), 'ino' => (int) ($stat['ino'] ?? 0), 'type' => ((int) ($stat['mode'] ?? 0)) & 0170000];
    }

    private function matchesIdentity(string $path, ?array $expected): bool
    {
        if (!is_array($expected) || ($expected['ino'] ?? 0) === 0) return false;
        $current = $this->captureIdentity($path);
        return is_array($current) && $current['ino'] !== 0
            && $current['dev'] === $expected['dev']
            && $current['ino'] === $expected['ino']
            && $current['type'] === $expected['type'];
    }
}