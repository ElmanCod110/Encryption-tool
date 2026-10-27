<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Security\Validator;
use Throwable;

/**
 * Writes the frozen, single-file binary package format. The current V14 writer
 * remains untouched until this implementation and its adversarial tests pass.
 */
final class StablePackageWriter
{
    public function build(
        string $sourceDir,
        string $destinationFile,
        string $password,
        string $pattern,
        ?string $packageId = null,
        bool $createRecovery = true
    ): array {
        StablePackageDescriptor::assertRuntime();
        Validator::validatePassword($password);
        Validator::validatePattern($pattern);

        $sourceRoot = $this->canonicalSourceDirectory($sourceDir);
        $entries = $this->scanTree($sourceRoot);
        if (count($entries) < 1 || count($entries) > StablePackageDescriptor::MAX_NODES) {
            throw new RuntimeException('Source tree is empty or exceeds the package entry limit.');
        }
        usort($entries, static fn(array $a, array $b): int => strcmp($a['path'], $b['path']));

        $fileCount = 0;
        $directoryCount = 0;
        $totalPlainBytes = 0;
        foreach ($entries as &$entry) {
            if ($entry['type'] === 2) {
                $fileCount++;
                $totalPlainBytes += $entry['size'];
                if ($totalPlainBytes > StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES) {
                    throw new RuntimeException('Source tree exceeds the total package size limit.');
                }
                $entry['chunks'] = StablePackageDescriptor::expectedChunkCount($entry['size']);
            } else {
                $directoryCount++;
            }
        }
        unset($entry);
        if ($fileCount < 1) {
            throw new RuntimeException('A package must contain at least one regular file.');
        }

        $manifestEntries = [];
        foreach ($entries as $entry) {
            $manifestEntries[] = [
                'type' => $entry['type'],
                'id' => $entry['id'],
                'parent_id' => $entry['parent_id'],
                'name' => $entry['name'],
                'size' => $entry['type'] === 2 ? $entry['size'] : null,
                'chunks' => $entry['type'] === 2 ? $entry['chunks'] : null,
            ];
        }
        $manifestPlain = StablePackageDescriptor::encodeManifest($manifestEntries);
        // Validate the writer's own output against the same strict graph and canonical-order rules.
        $checkedManifest = StablePackageDescriptor::decodeManifest($manifestPlain);
        if ($checkedManifest['file_count'] !== $fileCount || $checkedManifest['directory_count'] !== $directoryCount
            || $checkedManifest['total_plain_bytes'] !== $totalPlainBytes) {
            throw new RuntimeException('Internal manifest validation failed.');
        }

        if ($packageId === null) {
            $packageIdRaw = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::PACKAGE_ID_BYTES);
            $packageId = bin2hex($packageIdRaw);
        } else {
            PackageId::assert($packageId);
            $packageIdRaw = hex2bin($packageId);
        }
        if (!is_string($packageIdRaw) || strlen($packageIdRaw) !== StablePackageDescriptor::PACKAGE_ID_BYTES
            || StablePackageDescriptor::isZeroBytes($packageIdRaw)) {
            throw new RuntimeException('Invalid package identifier.');
        }

        $destination = $this->canonicalDestinationFile($destinationFile);
        if (file_exists($destination) || is_link($destination)) {
            throw new RuntimeException('Package destination already exists.');
        }

        $salt = null;
        $rootKey = null;
        $credentialKey = null;
        $manifestKey = null;
        $headerMacKey = null;
        $recoveryKeyRaw = null;
        $temporaryFile = $destination . '.partial.' . bin2hex(random_bytes(16));
        $out = null;
        $temporaryCreated = false;
        $temporaryIdentity = null;
        $published = false;

        try {
            $salt = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::SALT_BYTES);
            $rootKey = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::KEY_BYTES);
            $recoveryKeyRaw = $createRecovery ? StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::KEY_BYTES) : null;
            $ops = StablePackageDescriptor::DEFAULT_KDF_OPS;
            $memory = StablePackageDescriptor::DEFAULT_KDF_MEM_BYTES;
            StablePackageDescriptor::assertKdfParameters($ops, $memory);
            $flags = $createRecovery ? StablePackageDescriptor::FLAG_RECOVERY_SLOT : 0;
            $core = StablePackageDescriptor::MAGIC
                . chr($flags)
                . chr(StablePackageDescriptor::KDF_ARGON2ID13)
                . chr(StablePackageDescriptor::AEAD_XCHACHA20POLY1305)
                . chr(StablePackageDescriptor::STREAM_SECRETSTREAM_XCHACHA20POLY1305)
                . chr(StablePackageDescriptor::HASH_SHA256)
                . pack('N2', $ops, $memory)
                . $packageIdRaw
                . $salt;
            if (strlen($core) !== StablePackageDescriptor::CORE_BYTES) {
                throw new RuntimeException('Internal stable header layout mismatch.');
            }
            $coreHash = hash('sha256', $core, true);
            $credentialKey = StablePackageCrypto::deriveCredentialKey($password, $pattern, $salt, $packageIdRaw, $ops, $memory);

            $primaryNonce = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::NONCE_BYTES);
            $primaryCipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $rootKey,
                "SPKG/KEYWRAP/PRIMARY\0" . $core,
                $primaryNonce,
                $credentialKey
            );
            if (strlen($primaryCipher) !== StablePackageDescriptor::WRAPPED_KEY_BYTES) {
                throw new RuntimeException('Unable to wrap package key.');
            }

            if ($recoveryKeyRaw !== null) {
                $recoveryNonce = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::NONCE_BYTES);
                $recoveryCipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                    $rootKey,
                    "SPKG/KEYWRAP/RECOVERY\0" . $core,
                    $recoveryNonce,
                    $recoveryKeyRaw
                );
            } else {
                $recoveryNonce = str_repeat("\0", StablePackageDescriptor::NONCE_BYTES);
                $recoveryCipher = str_repeat("\0", StablePackageDescriptor::WRAPPED_KEY_BYTES);
            }
            $headerWithoutMac = $core . $primaryNonce . $primaryCipher . $recoveryNonce . $recoveryCipher;
            if (strlen($headerWithoutMac) !== StablePackageDescriptor::HEADER_WITHOUT_MAC_BYTES) {
                throw new RuntimeException('Internal stable header layout mismatch.');
            }
            $headerMacKey = StablePackageCrypto::deriveSubkey($rootKey, 'HEADER-MAC', $packageIdRaw);
            $headerMac = hash_hmac('sha256', $headerWithoutMac, $headerMacKey, true);
            $header = $headerWithoutMac . $headerMac;
            if (strlen($header) !== StablePackageDescriptor::HEADER_BYTES) {
                throw new RuntimeException('Internal stable header length mismatch.');
            }

            $manifestKey = StablePackageCrypto::deriveSubkey($rootKey, 'MANIFEST', $packageIdRaw);
            $out = @fopen($temporaryFile, 'x+b');
            if ($out === false) {
                $out = null;
                throw new RuntimeException('Unable to create temporary package file.');
            }
            $temporaryCreated = true;
            $temporaryStat = fstat($out);
            $temporaryPathStat = @lstat($temporaryFile);
            if (!is_array($temporaryStat) || !is_array($temporaryPathStat) || is_link($temporaryFile)
                || (((int) ($temporaryStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (((int) ($temporaryPathStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($temporaryStat['ino'] ?? 0) === 0
                || (int) ($temporaryStat['dev'] ?? -2) !== (int) ($temporaryPathStat['dev'] ?? -1)
                || (int) ($temporaryStat['ino'] ?? -1) !== (int) ($temporaryPathStat['ino'] ?? 0)) {
                throw new RuntimeException('Temporary package file identity could not be verified.');
            }
            $temporaryIdentity = [
                'dev' => (int) ($temporaryStat['dev'] ?? -1),
                'ino' => (int) $temporaryStat['ino'],
                'type' => ((int) ($temporaryStat['mode'] ?? 0)) & 0170000,
            ];
            $this->enforcePrivateFileMode($temporaryFile, 0600, $temporaryIdentity);
            StablePackageDescriptor::writeAll($out, $header);

            $fileRootKey = StablePackageCrypto::deriveSubkey($rootKey, 'FILE-ROOT', $packageIdRaw);
            try {
                foreach ($entries as $entry) {
                    if ($entry['type'] !== 2) {
                        continue;
                    }
                    $this->encryptFileEntry($out, $entry, $fileRootKey, $packageIdRaw, $coreHash);
                }
            } finally {
                sodium_memzero($fileRootKey);
            }

            $manifestNonce = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::NONCE_BYTES);
            $manifestCipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $manifestPlain,
                "SPKG/MANIFEST\0" . $coreHash,
                $manifestNonce,
                $manifestKey
            );
            $this->writeRecord($out, StablePackageDescriptor::RECORD_MANIFEST, $manifestNonce . $manifestCipher,
                StablePackageDescriptor::MAX_MANIFEST_RECORD_BYTES);

            if (!fflush($out)) {
                throw new RuntimeException('Unable to flush the package file.');
            }
            if (function_exists('fsync') && !fsync($out)) {
                throw new RuntimeException('Unable to synchronize the package file.');
            }
            if (!fclose($out)) {
                $out = null;
                throw new RuntimeException('Unable to close the package file.');
            }
            $out = null;
            $this->publishWithoutReplace($temporaryFile, $destination, $temporaryIdentity);
            $published = true;

            return [
                'package_id' => $packageId,
                'files' => $fileCount,
                'directories' => $directoryCount,
                'nodes' => count($entries),
                'total_plain_bytes' => $totalPlainBytes,
                'recovery_key' => $recoveryKeyRaw === null ? null : StablePackageCrypto::encodeRecoveryKey($recoveryKeyRaw),
            ];
        } catch (Throwable $e) {
            if (is_resource($out)) {
                fclose($out);
            }
            $cleanupFailed = false;
            if (!$published && $temporaryCreated && (file_exists($temporaryFile) || is_link($temporaryFile))) {
                if (is_array($temporaryIdentity)
                    && $this->matchesPathIdentity($temporaryFile, $temporaryIdentity)) {
                    if (!@unlink($temporaryFile)) {
                        $cleanupFailed = true;
                    }
                } else {
                    // Never unlink a name that no longer points to the inode we created.
                    $cleanupFailed = true;
                }
            }
            if ($cleanupFailed) {
                throw new RuntimeException(
                    'Package creation failed and temporary output could not be safely removed.',
                    0,
                    $e
                );
            }
            throw $e;
        } finally {
            if (is_string($salt)) sodium_memzero($salt);
            if (is_string($rootKey)) sodium_memzero($rootKey);
            if (is_string($credentialKey)) sodium_memzero($credentialKey);
            if (is_string($manifestKey)) sodium_memzero($manifestKey);
            if (is_string($headerMacKey)) sodium_memzero($headerMacKey);
            if (is_string($recoveryKeyRaw)) sodium_memzero($recoveryKeyRaw);
            if (is_string($manifestPlain)) sodium_memzero($manifestPlain);
            $password = '';
            $pattern = '';
        }
    }

    private function encryptFileEntry($out, array $entry, string $fileRootKey, string $packageId, string $coreHash): void
    {
        $path = $entry['source_path'];
        if (is_link($path) || !is_file($path)) {
            throw new RuntimeException('Source entry changed during package creation.');
        }
        $real = realpath($path);
        $root = $entry['source_root'];
        $rootPrefix = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $realNormalized = $real === false ? '' : str_replace('\\', '/', $real);
        if ($real === false || !str_starts_with($realNormalized, $rootPrefix)) {
            throw new RuntimeException('Source entry escaped the source directory.');
        }
        $input = @fopen($path, 'rb');
        if ($input === false) {
            throw new RuntimeException('Unable to open source file.');
        }
        // Compare the opened handle with the no-follow path identity captured during
        // enumeration. This detects common symlink/replacement races before any plaintext
        // from a substituted file is encrypted into the package.
        $pathStat = @lstat($path);
        $before = fstat($input);
        $expectedDev = $entry['source_dev'] ?? null;
        $expectedIno = $entry['source_ino'] ?? null;
        $identityMatches = is_array($pathStat) && is_array($before)
            && !is_link($path)
            && ($pathStat['dev'] ?? null) === ($before['dev'] ?? null)
            && ($pathStat['ino'] ?? null) === ($before['ino'] ?? null)
            && ($before['dev'] ?? null) === $expectedDev
            && ($before['ino'] ?? null) === $expectedIno
            && (((int) ($before['mode'] ?? 0) & 0170000) === 0100000);
        if (!$identityMatches || !is_array($before) || (int) ($before['size'] ?? -1) !== $entry['size']) {
            fclose($input);
            throw new RuntimeException('Source file changed during package creation.');
        }

        $fileKey = StablePackageCrypto::deriveSubkey($fileRootKey, 'FILE', $packageId, bin2hex($entry['id']));
        $state = null;
        try {
            [$state, $streamHeader] = sodium_crypto_secretstream_xchacha20poly1305_init_push($fileKey);
            $startBody = $entry['id'] . StablePackageDescriptor::packUint64($entry['size']) . $streamHeader;
            $this->writeRecord($out, StablePackageDescriptor::RECORD_FILE_START, $startBody,
                StablePackageDescriptor::MAX_FILE_CHUNK_RECORD_BYTES);

            $sourceHash = hash_init('sha256');
            $remaining = $entry['size'];
            $sequence = 0;
            if ($remaining === 0) {
                $cipher = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $state,
                    '',
                    StablePackageCrypto::chunkAad($coreHash, $packageId, $entry['id'], $sequence, 0),
                    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                );
                $this->writeChunkRecord($out, $entry['id'], $sequence, $cipher);
                $sequence++;
            } else {
                while ($remaining > 0) {
                    $wanted = min(StablePackageDescriptor::CHUNK_BYTES, $remaining);
                    $plain = $this->readExactFromFile($input, $wanted);
                    try {
                        hash_update($sourceHash, $plain);
                        $remaining -= strlen($plain);
                        if (strlen($plain) !== $wanted) {
                            throw new RuntimeException('Source file changed during package creation.');
                        }
                        $tag = $remaining === 0
                            ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                            : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                        $cipher = sodium_crypto_secretstream_xchacha20poly1305_push(
                            $state,
                            $plain,
                            StablePackageCrypto::chunkAad($coreHash, $packageId, $entry['id'], $sequence, $entry['size']),
                            $tag
                        );
                        $this->writeChunkRecord($out, $entry['id'], $sequence, $cipher);
                        $sequence++;
                    } finally {
                        if ($plain !== '') sodium_memzero($plain);
                    }
                }
            }
            if ($sequence !== $entry['chunks']) {
                throw new RuntimeException('Internal file chunk count mismatch.');
            }
            $extra = fread($input, 1);
            if ($extra === false || $extra !== '') {
                throw new RuntimeException('Source file changed during package creation.');
            }
            // Also verify the path still names the exact inode opened above. Checking only
            // fstat() would miss replacement of the directory entry while its old handle
            // remained readable.
            clearstatcache(true, $path);
            $pathAfter = @lstat($path);
            $realAfter = realpath($path);
            $realAfterNormalized = $realAfter === false ? '' : str_replace('\\', '/', $realAfter);
            $rootPrefixAfter = rtrim(str_replace('\\', '/', $root), '/') . '/';
            if (!is_array($pathAfter) || is_link($path)
                || (int) ($pathAfter['dev'] ?? -2) !== (int) ($before['dev'] ?? -1)
                || (int) ($pathAfter['ino'] ?? 0) !== (int) ($before['ino'] ?? 0)
                || (((int) ($pathAfter['mode'] ?? 0) & 0170000) !== 0100000)
                || $realAfter === false || !str_starts_with($realAfterNormalized, $rootPrefixAfter)) {
                throw new RuntimeException('Source path changed during package creation.');
            }
            $after = fstat($input);
            if (!is_array($after) || (int) ($after['dev'] ?? -2) !== (int) ($before['dev'] ?? -1)
                || (int) ($after['ino'] ?? 0) !== (int) ($before['ino'] ?? -1)
                || (int) ($after['size'] ?? -1) !== $entry['size']
                || (int) ($after['mtime'] ?? -1) !== (int) ($before['mtime'] ?? -1)
                || (int) ($after['ctime'] ?? -1) !== (int) ($before['ctime'] ?? -1)) {
                throw new RuntimeException('Source file changed during package creation.');
            }

            // Timestamp granularity can be coarse on some filesystems. Hash the exact
            // plaintext read into the stream and compare it with a fresh streaming read,
            // so same-size in-place changes are not missed merely because timestamps match.
            $expectedDigest = hash_final($sourceHash, true);
            try {
                $this->verifySourceDigest($path, $root, $before, $expectedDigest);
            } finally {
                sodium_memzero($expectedDigest);
            }
        } finally {
            fclose($input);
            sodium_memzero($fileKey);
            if (is_string($state)) sodium_memzero($state);
        }
    }

    private function verifySourceDigest(string $path, string $root, array $expectedStat, string $expectedDigest): void
    {
        if (is_link($path)) {
            throw new RuntimeException('Source file changed during package creation.');
        }
        $realBefore = realpath($path);
        $rootPrefix = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $realBeforeNormalized = $realBefore === false ? '' : str_replace('\\', '/', $realBefore);
        if ($realBefore === false || !str_starts_with($realBeforeNormalized, $rootPrefix)) {
            throw new RuntimeException('Source file escaped the source directory during verification.');
        }

        $verify = @fopen($path, 'rb');
        if ($verify === false) {
            throw new RuntimeException('Unable to verify source file stability.');
        }
        try {
            clearstatcache(true, $path);
            $pathStat = @lstat($path);
            $openedStat = fstat($verify);
            $matchesExpected = is_array($pathStat) && is_array($openedStat) && !is_link($path)
                && (((int) ($pathStat['mode'] ?? 0) & 0170000) === 0100000)
                && (((int) ($openedStat['mode'] ?? 0) & 0170000) === 0100000)
                && (int) ($pathStat['dev'] ?? -2) === (int) ($openedStat['dev'] ?? -1)
                && (int) ($pathStat['ino'] ?? 0) === (int) ($openedStat['ino'] ?? -1)
                && (int) ($openedStat['dev'] ?? -2) === (int) ($expectedStat['dev'] ?? -1)
                && (int) ($openedStat['ino'] ?? 0) === (int) ($expectedStat['ino'] ?? -1)
                && (int) ($openedStat['size'] ?? -1) === (int) ($expectedStat['size'] ?? -2)
                && (int) ($openedStat['mtime'] ?? -1) === (int) ($expectedStat['mtime'] ?? -2)
                && (int) ($openedStat['ctime'] ?? -1) === (int) ($expectedStat['ctime'] ?? -2);
            if (!$matchesExpected) {
                throw new RuntimeException('Source file changed before content verification.');
            }

            $context = hash_init('sha256');
            $bytesRead = 0;
            while (!feof($verify)) {
                $buffer = fread($verify, 1_048_576);
                if ($buffer === false) {
                    throw new RuntimeException('Unable to verify source file contents.');
                }
                if ($buffer === '') {
                    if (feof($verify)) {
                        break;
                    }
                    throw new RuntimeException('Source file verification stalled.');
                }
                try {
                    $bytesRead += strlen($buffer);
                    if ($bytesRead > (int) ($expectedStat['size'] ?? -1)) {
                        throw new RuntimeException('Source file grew during content verification.');
                    }
                    hash_update($context, $buffer);
                } finally {
                    sodium_memzero($buffer);
                }
            }

            clearstatcache(true, $path);
            $pathAfter = @lstat($path);
            $after = fstat($verify);
            $realAfter = realpath($path);
            $realAfterNormalized = $realAfter === false ? '' : str_replace('\\', '/', $realAfter);
            if (!is_array($pathAfter) || !is_array($after) || is_link($path)
                || (int) ($pathAfter['dev'] ?? -2) !== (int) ($expectedStat['dev'] ?? -1)
                || (int) ($pathAfter['ino'] ?? 0) !== (int) ($expectedStat['ino'] ?? -1)
                || (((int) ($pathAfter['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($after['dev'] ?? -2) !== (int) ($expectedStat['dev'] ?? -1)
                || (int) ($after['ino'] ?? 0) !== (int) ($expectedStat['ino'] ?? -1)
                || (int) ($after['size'] ?? -1) !== (int) ($expectedStat['size'] ?? -2)
                || (int) ($after['mtime'] ?? -1) !== (int) ($expectedStat['mtime'] ?? -2)
                || (int) ($after['ctime'] ?? -1) !== (int) ($expectedStat['ctime'] ?? -2)
                || $bytesRead !== (int) ($expectedStat['size'] ?? -1)
                || $realAfter === false || !str_starts_with($realAfterNormalized, $rootPrefix)) {
                throw new RuntimeException('Source file changed during content verification.');
            }

            $actualDigest = hash_final($context, true);
            try {
                if (!hash_equals($expectedDigest, $actualDigest)) {
                    throw new RuntimeException('Source content changed during package creation.');
                }
            } finally {
                sodium_memzero($actualDigest);
            }
        } finally {
            fclose($verify);
        }
    }

    private function scanTree(string $root): array
    {
        $entries = [];
        $seenIds = [];
        $nodeCount = 0;
        $pendingCount = 0;
        $totalBytes = 0;
        $rootStat = @lstat($root);
        if (!is_array($rootStat) || is_link($root)
            || (((int) ($rootStat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Source root is not a stable directory.');
        }
        $rootDev = (int) ($rootStat['dev'] ?? -1);
        $rootIno = (int) ($rootStat['ino'] ?? 0);
        $rootNormalized = str_replace('\\', '/', $root);
        $rootPrefix = rtrim($rootNormalized, '/') . '/';
        $walk = function (string $directory, string $parentId, string $relative, int $depth,
            int $expectedDev, int $expectedIno) use (&$walk, &$entries, &$seenIds, &$nodeCount, &$pendingCount, &$totalBytes, $root, $rootPrefix): void {
            // PHP lacks a portable openat(O_NOFOLLOW) tree-walk API. Verify directory
            // identity immediately before and after enumeration and before descending.
            $beforeDir = @lstat($directory);
            $realBefore = realpath($directory);
            $realBeforeNormalized = $realBefore === false ? '' : str_replace('\\', '/', $realBefore);
            if (!is_array($beforeDir) || is_link($directory)
                || (((int) ($beforeDir['mode'] ?? 0) & 0170000) !== 0040000)
                || (int) ($beforeDir['dev'] ?? -2) !== $expectedDev
                || (int) ($beforeDir['ino'] ?? 0) !== $expectedIno
                || $realBefore === false
                || ($directory !== $root && !str_starts_with($realBeforeNormalized, $rootPrefix))
                || ($directory === $root && $realBeforeNormalized !== str_replace('\\', '/', $root))) {
                throw new RuntimeException('Source directory changed or escaped during package creation.');
            }
            // Read directory entries incrementally. The global pending count includes
            // siblings still held by ancestor frames, so a wide directory cannot allocate
            // an unbounded array before MAX_NODES is enforced.
            $directoryHandle = @opendir($directory);
            if ($directoryHandle === false) {
                throw new RuntimeException('Unable to inspect the source directory.');
            }
            $names = [];
            try {
                while (($name = readdir($directoryHandle)) !== false) {
                    if ($name === '.' || $name === '..') {
                        continue;
                    }
                    if ($nodeCount + $pendingCount >= StablePackageDescriptor::MAX_NODES) {
                        throw new RuntimeException('Source tree contains too many entries.');
                    }
                    $names[] = $name;
                    $pendingCount++;
                }
            } finally {
                closedir($directoryHandle);
            }
            $afterDir = @lstat($directory);
            if (!is_array($afterDir) || is_link($directory)
                || (int) ($afterDir['dev'] ?? -2) !== $expectedDev
                || (int) ($afterDir['ino'] ?? 0) !== $expectedIno
                || (((int) ($afterDir['mode'] ?? 0) & 0170000) !== 0040000)) {
                throw new RuntimeException('Source directory changed during enumeration.');
            }
            $names = array_values(array_diff($names, ['.', '..']));
            sort($names, SORT_STRING);
            $siblings = [];
            foreach ($names as $name) {
                $pendingCount--;
                StablePackageDescriptor::assertName($name);
                $fold = StablePackageDescriptor::foldName($name);
                if (isset($siblings[$fold])) {
                    throw new RuntimeException('Source directory contains colliding names.');
                }
                $siblings[$fold] = true;

                $path = $directory . DIRECTORY_SEPARATOR . $name;
                $entryStat = @lstat($path);
                if (!is_array($entryStat) || is_link($path)) {
                    throw new RuntimeException('Symbolic links or unstable source entries are not supported.');
                }
                $entryType = ((int) ($entryStat['mode'] ?? 0)) & 0170000;
                $isDirectory = $entryType === 0040000;
                $isFile = $entryType === 0100000;
                if (!$isDirectory && !$isFile) {
                    throw new RuntimeException('Special filesystem entries are not supported.');
                }
                $real = realpath($path);
                $realNormalized = $real === false ? '' : str_replace('\\', '/', $real);
                if ($real === false || !str_starts_with($realNormalized, $rootPrefix)) {
                    throw new RuntimeException('Source entry escaped the source directory.');
                }
                $nodeDepth = $depth;
                if ($nodeDepth > StablePackageDescriptor::MAX_DEPTH) {
                    throw new RuntimeException('Source directory nesting exceeds the package limit.');
                }
                if (++$nodeCount > StablePackageDescriptor::MAX_NODES) {
                    throw new RuntimeException('Source tree contains too many entries.');
                }
                $id = '';
                $idHex = '';
                for ($attempt = 0; $attempt < 32; $attempt++) {
                    $id = StablePackageDescriptor::randomNonZeroBytes(StablePackageDescriptor::FILE_ID_BYTES);
                    $idHex = bin2hex($id);
                    if (!isset($seenIds[$idHex])) {
                        break;
                    }
                }
                if ($id === '' || isset($seenIds[$idHex])) {
                    throw new RuntimeException('Unable to generate a unique file identifier.');
                }
                $seenIds[$idHex] = true;
                $pathName = $relative === '' ? $name : $relative . '/' . $name;
                if (strlen($pathName) > StablePackageDescriptor::MAX_PATH_BYTES) {
                    throw new RuntimeException('Source path exceeds the package limit.');
                }
                $entry = [
                    'type' => $isDirectory ? 1 : 2,
                    'id' => $id,
                    'parent_id' => $parentId,
                    'name' => $name,
                    'path' => $pathName,
                    'source_path' => $path,
                    'source_root' => $root,
                    'source_dev' => (int) ($entryStat['dev'] ?? -1),
                    'source_ino' => (int) ($entryStat['ino'] ?? 0),
                    'size' => 0,
                    'chunks' => null,
                ];
                if ($isFile) {
                    if (!isset($entryStat['size']) || (int) $entryStat['size'] < 0
                        || (int) $entryStat['size'] > StablePackageDescriptor::MAX_FILE_BYTES) {
                        throw new RuntimeException('Source file exceeds the supported size limit.');
                    }
                    $entry['size'] = (int) $entryStat['size'];
                    $totalBytes += $entry['size'];
                    if ($totalBytes > StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES) {
                        throw new RuntimeException('Source tree exceeds the total package size limit.');
                    }
                }
                $entries[] = $entry;
                if ($isDirectory) {
                    $childStat = @lstat($path);
                    $childReal = realpath($path);
                    $childRealNormalized = $childReal === false ? '' : str_replace('\\', '/', $childReal);
                    if (!is_array($childStat) || is_link($path)
                        || (int) ($childStat['dev'] ?? -2) !== (int) ($entryStat['dev'] ?? -1)
                        || (int) ($childStat['ino'] ?? 0) !== (int) ($entryStat['ino'] ?? 0)
                        || (((int) ($childStat['mode'] ?? 0) & 0170000) !== 0040000)
                        || $childReal === false || !str_starts_with($childRealNormalized, $rootPrefix)) {
                        throw new RuntimeException('Source directory changed before descent.');
                    }
                    $walk($path, $id, $pathName, $depth + 1,
                        (int) ($entryStat['dev'] ?? -1), (int) ($entryStat['ino'] ?? 0));
                }
            }
        };
        $walk($root, StablePackageDescriptor::zeroId(), '', 1, $rootDev, $rootIno);
        return $entries;
    }

    private function canonicalSourceDirectory(string $sourceDir): string
    {
        if (is_link($sourceDir)) {
            throw new RuntimeException('Source directory must not be a symbolic link.');
        }
        $real = realpath($sourceDir);
        if ($real === false || !is_dir($real)) {
            throw new RuntimeException('Source directory does not exist.');
        }
        $trimmed = rtrim($real, DIRECTORY_SEPARATOR);
        if ($trimmed === '') {
            return DIRECTORY_SEPARATOR;
        }
        // On Windows, trimming the root separator from "C:\\" yields "C:",
        // which has drive-relative rather than drive-root semantics.
        if (DIRECTORY_SEPARATOR === '\\\\' && preg_match('/^[A-Za-z]:$/D', $trimmed) === 1) {
            return $trimmed . DIRECTORY_SEPARATOR;
        }
        return $trimmed;
    }

    private function canonicalDestinationFile(string $path): string
    {
        $parent = realpath(dirname($path));
        $name = basename($path);
        if ($parent === false || !is_dir($parent) || $name === '' || $name === '.' || $name === '..') {
            throw new RuntimeException('Package destination parent is invalid.');
        }
        return rtrim($parent, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
    }

    private function writeChunkRecord($out, string $fileId, int $sequence, string $cipher): void
    {
        $body = $fileId . pack('N', $sequence) . $cipher;
        $this->writeRecord($out, StablePackageDescriptor::RECORD_FILE_CHUNK, $body,
            StablePackageDescriptor::MAX_FILE_CHUNK_RECORD_BYTES);
    }

    private function writeRecord($out, int $type, string $body, int $maximum): void
    {
        $length = strlen($body);
        if ($length < 1 || $length > $maximum || $length > 0xFFFFFFFF) {
            throw new RuntimeException('Package record length is invalid.');
        }
        StablePackageDescriptor::writeAll($out, chr($type) . pack('N', $length) . $body);
    }

    private function readExactFromFile($handle, int $length): string
    {
        return StablePackageDescriptor::readExact($handle, $length);
    }

    private function publishWithoutReplace(string $temporary, string $destination, ?array $expectedIdentity): void
    {
        if (!is_array($expectedIdentity) || !$this->matchesPathIdentity($temporary, $expectedIdentity)) {
            throw new RuntimeException('Temporary package identity changed before publication.');
        }
        if (file_exists($destination) || is_link($destination)) {
            throw new RuntimeException('Package destination already exists.');
        }
        // Hard-link publication is atomic and fails if the destination exists. Verify
        // that the published name is still the inode produced by this writer.
        if (!@link($temporary, $destination)) {
            throw new RuntimeException('Unable to publish package without overwriting an existing destination.');
        }
        if (!$this->matchesPathIdentity($destination, $expectedIdentity)) {
            throw new RuntimeException('Published package identity could not be verified safely.');
        }
        if (!$this->matchesPathIdentity($temporary, $expectedIdentity) || !@unlink($temporary)) {
            // Remove only the destination name if it still points to the inode we created.
            if ($this->matchesPathIdentity($destination, $expectedIdentity)) {
                @unlink($destination);
            }
            throw new RuntimeException('Package publication cleanup failed.');
        }
    }

    private function enforcePrivateFileMode(string $path, int $mode, ?array $expectedIdentity): void
    {
        if (!$this->matchesPathIdentity($path, $expectedIdentity) || !@chmod($path, $mode)) {
            throw new RuntimeException('Unable to set private package file permissions safely.');
        }
        clearstatcache(true, $path);
        if (!$this->matchesPathIdentity($path, $expectedIdentity)) {
            throw new RuntimeException('Temporary package path changed during permission hardening.');
        }
        // PHP exposes no portable Windows ACL API. On POSIX systems, verify that group
        // and other permissions are absent rather than trusting chmod's return alone.
        if (DIRECTORY_SEPARATOR !== '\\\\') {
            $permissions = @fileperms($path);
            if (!is_int($permissions) || (($permissions & 0777) !== ($mode & 0777))) {
                throw new RuntimeException('Private package file permissions did not take effect.');
            }
        }
    }

    private function matchesPathIdentity(string $path, ?array $expected): bool
    {
        if (!is_array($expected) || (int) ($expected['ino'] ?? 0) === 0) {
            return false;
        }
        clearstatcache(true, $path);
        $actual = @lstat($path);
        return is_array($actual) && !is_link($path)
            && (((int) ($actual['mode'] ?? 0) & 0170000) === 0100000)
            && (int) ($actual['dev'] ?? -2) === (int) ($expected['dev'] ?? -1)
            && (int) ($actual['ino'] ?? 0) === (int) $expected['ino']
            && (((int) ($expected['type'] ?? 0)) === 0100000);
    }
}
