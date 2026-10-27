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
        $stageIdentity = null;
        $stageOwnedFiles = [];
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
            // Bind the canonical path to the opened regular file. If the path was
            // replaced with a symlink or a different inode between realpath() and
            // fopen(), fail before parsing any bytes from that unexpected target.
            clearstatcache(true, $source);
            $pathStat = @lstat($source);
            $fileStat = fstat($input);
            if (!is_array($pathStat) || !is_array($fileStat) || is_link($source)
                || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (((int) ($fileStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($pathStat['dev'] ?? -2) !== (int) ($fileStat['dev'] ?? -1)
                || (int) ($pathStat['ino'] ?? 0) !== (int) ($fileStat['ino'] ?? -1)
                || !isset($fileStat['size'])
                || (int) $fileStat['size'] < StablePackageDescriptor::HEADER_BYTES
                || (int) $fileStat['size'] > StablePackageDescriptor::MAX_PACKAGE_BYTES) {
                throw new RuntimeException('Package file identity or size is outside the supported bounds.');
            }
            $rawHeader = StablePackageDescriptor::readExact($input, StablePackageDescriptor::HEADER_BYTES);
            $header = StablePackageDescriptor::parseHeader($rawHeader);
            $rootKey = StablePackageCrypto::unwrapRootKey($header, $password, $pattern, $recoveryKey);
            $manifestKey = StablePackageCrypto::deriveSubkey($rootKey, 'MANIFEST', $header['package_id']);
            $fileRootKey = StablePackageCrypto::deriveSubkey($rootKey, 'FILE-ROOT', $header['package_id']);
            $stageInfo = $this->createPrivateStage();
            $stage = $stageInfo['path'];
            $stageIdentity = $stageInfo['identity'];

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
                    if (StablePackageDescriptor::isZeroBytes($fileId)
                        || StablePackageDescriptor::isZeroBytes($streamHeader)
                        || isset($observedIds[$fileIdHex])
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
                        if (is_string($streamState)) sodium_memzero($streamState);
                        throw new RuntimeException('Unable to stage decrypted file.');
                    }
                    $stageHandleStat = fstat($out);
                    if (!is_array($stageHandleStat)
                        || (((int) ($stageHandleStat['mode'] ?? 0) & 0170000) !== 0100000)
                        || (int) ($stageHandleStat['ino'] ?? 0) === 0) {
                        fclose($out);
                        sodium_memzero($fileKey);
                        if (is_string($streamState)) sodium_memzero($streamState);
                        throw new RuntimeException('Staged file handle identity could not be verified.');
                    }
                    $stagedFileIdentity = [
                        'dev' => (int) ($stageHandleStat['dev'] ?? -1),
                        'ino' => (int) $stageHandleStat['ino'],
                        'type' => ((int) ($stageHandleStat['mode'] ?? 0)) & 0170000,
                    ];
                    try {
                        if (!$this->matchesIdentity($stagePath, $stagedFileIdentity)) {
                            throw new RuntimeException('Staged file path does not match the exclusive-create handle.');
                        }
                        $stageOwnedFiles[$fileIdHex] = ['path' => $stagePath, 'identity' => $stagedFileIdentity];
                        $this->enforcePrivateMode($stagePath, 0600, $stagedFileIdentity);
                    } catch (Throwable $stageError) {
                        fclose($out);
                        sodium_memzero($fileKey);
                        if (is_string($streamState)) sodium_memzero($streamState);
                        throw $stageError;
                    }
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
                        'stage_identity' => $stagedFileIdentity,
                        'hash' => hash_init('sha256'),
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

                        // Keep a digest of the exact authenticated plaintext bytes. The
                        // private staging path is reopened later for publication, so we must
                        // detect in-place changes to staging data as well as path replacement.
                        hash_update($active['hash'], $plain);
                        if ($plainLength > 0) {
                            StablePackageDescriptor::writeAll($active['out'], $plain);
                        }
                        $active['written'] = $newTotal;
                        $active['chunks']++;
                    } finally {
                        if ($plain !== '') sodium_memzero($plain);
                    }

                    if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                        $outputStat = is_resource($active['out']) ? fstat($active['out']) : false;
                        if (!is_array($outputStat)
                            || (int) ($outputStat['dev'] ?? -2) !== (int) ($active['stage_identity']['dev'] ?? -1)
                            || (int) ($outputStat['ino'] ?? 0) !== (int) ($active['stage_identity']['ino'] ?? -1)
                            || (int) ($outputStat['size'] ?? -1) !== $active['size']
                            || !$this->matchesIdentity($active['stage_path'], $active['stage_identity'])) {
                            throw new RuntimeException('Staged plaintext identity changed during decryption.');
                        }
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
                        $active['out'] = null;
                        if (!$this->matchesIdentity($active['stage_path'], $active['stage_identity'])
                            || is_link($active['stage_path']) || !is_file($active['stage_path'])) {
                            throw new RuntimeException('Staged plaintext path changed after close.');
                        }
                        $plainDigest = hash_final($active['hash'], true);
                        $active['hash'] = null;
                        $observedFiles[$active['id_hex']] = [
                            'size' => $active['size'],
                            'chunks' => $active['chunks'],
                            'path' => $active['stage_path'],
                            'identity' => $active['stage_identity'],
                            'sha256' => $plainDigest,
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
                    if (StablePackageDescriptor::isZeroBytes($nonce)) {
                        throw new RuntimeException('Manifest nonce is invalid.');
                    }
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
            $this->removePrivateStage($stage, $stageIdentity, $stageOwnedFiles);
            $stage = null;
            $stageIdentity = null;
            $stageOwnedFiles = [];

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
            if (is_string($stage) && (file_exists($stage) || is_link($stage))) {
                $this->removePrivateStage($stage, $stageIdentity, $stageOwnedFiles);
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
            $identity = $observed['identity'] ?? null;
            $digest = $observed['sha256'] ?? null;
            if (!is_string($idHex) || !preg_match('/^[a-f0-9]{32}$/D', $idHex)
                || !is_string($path) || is_link($path) || !is_file($path)
                || dirname($path) !== $stage || basename($path) !== $idHex . '.plain'
                || !is_array($identity) || !is_string($digest) || strlen($digest) !== 32
                || !$this->matchesIdentity($path, $identity)) {
                throw new RuntimeException('Private staging inventory is invalid.');
            }
            $filesById[$idHex] = ['path' => $path, 'identity' => $identity, 'sha256' => $digest];
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
        if (!is_array($createdRootIdentity) || $createdRootIdentity['type'] !== 0040000
            || is_link($destination) || !$this->matchesIdentity($destination, $createdRootIdentity)) {
            throw new RuntimeException('Unable to verify restore destination directory identity.');
        }
        $ownedDirectories = [$destination => $createdRootIdentity];
        $this->enforcePrivateMode($destination, 0700, $createdRootIdentity);

        $directories = array_values(array_filter($entries, static fn(array $entry): bool => $entry['type'] === 1));
        usort($directories, static fn(array $a, array $b): int => ($a['depth'] <=> $b['depth']) ?: strcmp($a['path'], $b['path']));
        foreach ($directories as $entry) {
            $target = $destination . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entry['path']);
            $parent = dirname($target);
            $parentIdentity = $ownedDirectories[$parent] ?? null;
            if (!is_dir($parent) || is_link($parent) || !$this->matchesIdentity($parent, $parentIdentity)
                || file_exists($target) || is_link($target) || !@mkdir($target, 0700)) {
                throw new RuntimeException('Unable to create restored directory safely.');
            }
            $identity = $this->captureIdentity($target);
            if (is_array($identity) && $identity['type'] === 0040000 && !is_link($target)) {
                $createdDirectories[] = ['path' => $target, 'identity' => $identity];
            }
            if (!is_array($identity) || $identity['type'] !== 0040000
                || is_link($target) || !$this->matchesIdentity($target, $identity)) {
                throw new RuntimeException('Unable to verify restored directory identity.');
            }
            $ownedDirectories[$target] = $identity;
            $this->enforcePrivateMode($target, 0700, $identity);
        }

        $files = array_values(array_filter($entries, static fn(array $entry): bool => $entry['type'] === 2));
        usort($files, static fn(array $a, array $b): int => strcmp($a['path'], $b['path']));
        foreach ($files as $entry) {
            $target = $destination . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entry['path']);
            $parent = dirname($target);
            $parentIdentity = $ownedDirectories[$parent] ?? null;
            if (!is_dir($parent) || is_link($parent) || !$this->matchesIdentity($parent, $parentIdentity)
                || file_exists($target) || is_link($target)) {
                throw new RuntimeException('Restored file destination is unsafe.');
            }
            $sourceInfo = $filesById[$entry['id_hex']] ?? null;
            $source = is_array($sourceInfo) ? ($sourceInfo['path'] ?? null) : null;
            $sourceIdentity = is_array($sourceInfo) ? ($sourceInfo['identity'] ?? null) : null;
            $expectedDigest = is_array($sourceInfo) ? ($sourceInfo['sha256'] ?? null) : null;
            if (!is_string($source) || is_link($source) || !is_file($source)
                || !is_array($sourceIdentity) || !is_string($expectedDigest) || strlen($expectedDigest) !== 32
                || !$this->matchesIdentity($source, $sourceIdentity)) {
                throw new RuntimeException('Authenticated file staging data is missing or changed.');
            }
            $in = @fopen($source, 'rb');
            $out = @fopen($target, 'xb');
            if ($in === false || $out === false) {
                if (is_resource($in)) fclose($in);
                if (is_resource($out)) fclose($out);
                // Never unlink $target here: fopen('xb') did not establish ownership if it failed.
                throw new RuntimeException('Unable to create restored file without overwriting.');
            }
            $inputStat = fstat($in);
            if (!is_array($inputStat)
                || (((int) ($inputStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($inputStat['dev'] ?? -2) !== (int) ($sourceIdentity['dev'] ?? -1)
                || (int) ($inputStat['ino'] ?? 0) !== (int) ($sourceIdentity['ino'] ?? -1)
                || !$this->matchesIdentity($source, $sourceIdentity)) {
                fclose($in);
                fclose($out);
                throw new RuntimeException('Staged plaintext handle does not match the verified file.');
            }
            $openedStat = fstat($out);
            if (!is_array($openedStat)
                || (((int) ($openedStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($openedStat['ino'] ?? 0) === 0) {
                fclose($in);
                fclose($out);
                throw new RuntimeException('Restored file handle identity could not be verified.');
            }
            // Record ownership from the already-open exclusive-create handle before
            // checking the directory entry. If the path is swapped, rollback may unlink
            // only when that name still points to this exact inode.
            $openedIdentity = [
                'dev' => (int) ($openedStat['dev'] ?? -1),
                'ino' => (int) $openedStat['ino'],
                'type' => ((int) ($openedStat['mode'] ?? 0)) & 0170000,
            ];
            $createdFiles[] = ['path' => $target, 'identity' => $openedIdentity];
            $targetIdentity = $this->captureIdentity($target);
            if (!is_array($targetIdentity)
                || ($targetIdentity['dev'] ?? null) !== $openedIdentity['dev']
                || ($targetIdentity['ino'] ?? null) !== $openedIdentity['ino']
                || ($targetIdentity['type'] ?? null) !== $openedIdentity['type']
                || !$this->matchesIdentity($target, $openedIdentity)) {
                fclose($in);
                fclose($out);
                throw new RuntimeException('Restored file path no longer matches the exclusively created file.');
            }
            try {
                $this->enforcePrivateMode($target, 0600, $openedIdentity);
            } catch (Throwable $permissionError) {
                fclose($in);
                fclose($out);
                throw $permissionError;
            }
            try {
                // Copy in bounded chunks and authenticate the staged bytes against the
                // digest accumulated from secretstream plaintext before publication.
                $copyHash = hash_init('sha256');
                $copied = 0;
                while (!feof($in)) {
                    $buffer = fread($in, 1_048_576);
                    if ($buffer === false) {
                        throw new RuntimeException('Unable to read authenticated staged plaintext.');
                    }
                    if ($buffer === '') {
                        if (feof($in)) {
                            break;
                        }
                        throw new RuntimeException('Staged plaintext copy stalled.');
                    }
                    try {
                        $copied += strlen($buffer);
                        if ($copied > $entry['size']) {
                            throw new RuntimeException('Staged plaintext exceeds the manifest size.');
                        }
                        hash_update($copyHash, $buffer);
                        StablePackageDescriptor::writeAll($out, $buffer);
                    } finally {
                        sodium_memzero($buffer);
                    }
                }
                $copiedDigest = hash_final($copyHash, true);
                try {
                    if ($copied !== $entry['size'] || !hash_equals($expectedDigest, $copiedDigest)) {
                        throw new RuntimeException('Staged plaintext changed after authentication.');
                    }
                } finally {
                    sodium_memzero($copiedDigest);
                }
                if (!$this->matchesIdentity($source, $sourceIdentity)) {
                    throw new RuntimeException('Staged plaintext path changed during publication.');
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
            if (is_link($target) || !$this->matchesIdentity($target, $targetIdentity) || !is_file($target)) {
                throw new RuntimeException('Restored file identity changed during publication.');
            }
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

    /** @return array{path:string, identity:array{dev:int,ino:int,type:int}} */
    private function createPrivateStage(): array
    {
        $base = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
        if ($base === '') {
            $base = DIRECTORY_SEPARATOR;
        }
        // Preserve a Windows drive root; "C:" is drive-relative, not "C:\\".
        if (DIRECTORY_SEPARATOR === '\\' && preg_match('/^[A-Za-z]:$/D', $base) === 1) {
            $base .= DIRECTORY_SEPARATOR;
        }
        $separator = str_ends_with($base, DIRECTORY_SEPARATOR) ? '' : DIRECTORY_SEPARATOR;
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $path = $base . $separator . 'spkg-stage-' . bin2hex(random_bytes(16));
            if (@mkdir($path, 0700)) {
                $identity = $this->captureIdentity($path);
                if (!is_array($identity) || $identity['type'] !== 0040000 || is_link($path)) {
                    // Without a stable identity, do not remove a path that may have been
                    // replaced after mkdir. The random name is not worth risking deletion
                    // of a directory that this process cannot prove it owns.
                    continue;
                }
                try {
                    $this->enforcePrivateMode($path, 0700, $identity);
                } catch (Throwable $e) {
                    if ($this->matchesIdentity($path, $identity) && !is_link($path) && !@rmdir($path)) {
                        throw new RuntimeException('Unable to remove private staging directory after setup failure.', 0, $e);
                    }
                    throw $e;
                }
                return ['path' => $path, 'identity' => $identity];
            }
        }
        throw new RuntimeException('Unable to create private staging directory.');
    }

    /**
     * Remove only registered files whose path still names the inode created here.
     * Unknown entries are never recursively deleted; if one appears, cleanup fails closed.
     */
    private function removePrivateStage(string $root, ?array $rootIdentity, array $ownedFiles): void
    {
        if (!file_exists($root) && !is_link($root)) {
            return;
        }
        if (is_link($root) || !is_dir($root) || !$this->matchesIdentity($root, $rootIdentity)) {
            throw new RuntimeException('Private staging directory identity changed; cleanup was refused.');
        }

        $failures = [];
        foreach ($ownedFiles as $idHex => $owned) {
            $path = $owned['path'] ?? null;
            $identity = $owned['identity'] ?? null;
            if (!is_string($idHex) || !preg_match('/^[a-f0-9]{32}$/D', $idHex)
                || !is_string($path) || dirname($path) !== $root || basename($path) !== $idHex . '.plain'
                || !is_array($identity)) {
                $failures[] = 'invalid-owned-entry';
                continue;
            }
            if (!file_exists($path) && !is_link($path)) {
                continue;
            }
            if (is_link($path) || !is_file($path) || !$this->matchesIdentity($path, $identity)) {
                $failures[] = $path;
                continue;
            }
            if (!@unlink($path)) {
                $failures[] = $path;
            }
        }

        $directory = @opendir($root);
        if ($directory === false) {
            throw new RuntimeException('Unable to inspect private staging directory for cleanup.');
        }
        $unknownEntryFound = false;
        try {
            while (($name = readdir($directory)) !== false) {
                if ($name !== '.' && $name !== '..') {
                    $unknownEntryFound = true;
                }
            }
        } finally {
            closedir($directory);
        }
        if ($unknownEntryFound) {
            $failures[] = 'unowned-staging-entry';
        }
        if ($failures !== []) {
            throw new RuntimeException('Private staging cleanup refused to delete unowned or changed paths.');
        }
        if (is_link($root) || !$this->matchesIdentity($root, $rootIdentity) || !is_dir($root)
            || !@rmdir($root)) {
            throw new RuntimeException('Unable to remove verified private staging directory.');
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

    private function enforcePrivateMode(string $path, int $mode, ?array $expectedIdentity): void
    {
        if (is_link($path) || !$this->matchesIdentity($path, $expectedIdentity) || !@chmod($path, $mode)) {
            throw new RuntimeException('Unable to set private restore permissions safely.');
        }
        clearstatcache(true, $path);
        if (is_link($path) || !$this->matchesIdentity($path, $expectedIdentity)) {
            throw new RuntimeException('Restore path changed during permission hardening.');
        }
        // PHP does not expose a portable Windows ACL API. On POSIX systems, confirm the
        // requested mode actually took effect and that group/other access was not retained.
        if (DIRECTORY_SEPARATOR !== '\\') {
            $permissions = @fileperms($path);
            if (!is_int($permissions) || (($permissions & 07777) !== ($mode & 07777))) {
                throw new RuntimeException('Private restore permissions did not take effect.');
            }
        }
    }

    private function captureIdentity(string $path): ?array
    {
        clearstatcache(true, $path);
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