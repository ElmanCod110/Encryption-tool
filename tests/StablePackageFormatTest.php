<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageDescriptor as Format;
use SecurePackage\Project\StablePackageReader;
use SecurePackage\Project\StablePackageWriter;

function stableAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function stableExpectFailure(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function stableCopy(string $from, string $to): void
{
    if (!copy($from, $to)) throw new RuntimeException('Unable to create tamper fixture.');
}

function stableMutateRecord(string $path, int $recordType, bool $lastByte = false): void
{
    $bytes = file_get_contents($path);
    if (!is_string($bytes) || strlen($bytes) < Format::HEADER_BYTES) throw new RuntimeException('Unable to read package fixture.');
    $offset = Format::HEADER_BYTES;
    $total = strlen($bytes);
    while ($offset < $total) {
        if ($offset + Format::RECORD_HEADER_BYTES > $total) throw new RuntimeException('Fixture record header is truncated.');
        $type = ord($bytes[$offset]);
        $length = unpack('Nvalue', substr($bytes, $offset + 1, 4))['value'] ?? 0;
        $bodyOffset = $offset + Format::RECORD_HEADER_BYTES;
        $end = $bodyOffset + $length;
        if ($length < 1 || $end > $total) throw new RuntimeException('Fixture record length is invalid.');
        if ($type === $recordType) {
            $position = $lastByte ? $end - 1 : $bodyOffset + ($type === Format::RECORD_FILE_CHUNK ? 20 : 0);
            if ($position >= $end) throw new RuntimeException('Fixture record payload is empty.');
            $bytes[$position] = chr(ord($bytes[$position]) ^ 0x01);
            if (file_put_contents($path, $bytes, LOCK_EX) !== strlen($bytes)) throw new RuntimeException('Unable to write tampered fixture.');
            return;
        }
        $offset = $end;
    }
    throw new RuntimeException('Requested record type was not found.');
}

function stableRemoveTree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    $items = scandir($path);
    if ($items === false) throw new RuntimeException('Unable to inspect test cleanup directory.');
    foreach (array_diff($items, ['.', '..']) as $item) stableRemoveTree($path . DIRECTORY_SEPARATOR . $item);
    if (!@rmdir($path)) throw new RuntimeException('Unable to remove test cleanup directory.');
}

Format::assertRuntime();
$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'stable-package-format-' . bin2hex(random_bytes(8));
$source = $root . DIRECTORY_SEPARATOR . 'source';
$package = $root . DIRECTORY_SEPARATOR . 'archive.spkg';
$restore = $root . DIRECTORY_SEPARATOR . 'restore';
$password = 'Strong!Password2026#';
$pattern = 'Az!71_xYp#42Qw9';
$wrongPassword = 'Wrong!Password2026#';
$wrongPattern = 'Qz!71_xYp#42Qw9';

mkdir($source . DIRECTORY_SEPARATOR . 'nested', 0700, true);
file_put_contents($source . DIRECTORY_SEPARATOR . 'hello.txt', "stable-format\n");
file_put_contents($source . DIRECTORY_SEPARATOR . 'empty.bin', '');
file_put_contents($source . DIRECTORY_SEPARATOR . 'nested' . DIRECTORY_SEPARATOR . 'binary.dat', random_bytes(Format::CHUNK_BYTES + 137));

try {
    $build = (new StablePackageWriter())->build($source, $package, $password, $pattern, str_repeat('a', 48), true);
    stableAssert($build['package_id'] === str_repeat('a', 48), 'Package id was not preserved.');
    stableAssert($build['files'] === 3 && $build['directories'] === 1 && $build['nodes'] === 4, 'Built statistics are invalid.');
    stableAssert(is_string($build['recovery_key']) && strlen($build['recovery_key']) === 43, 'Recovery key was not emitted as canonical base64url.');

    $raw = file_get_contents($package);
    stableAssert(is_string($raw) && strlen($raw) > Format::HEADER_BYTES, 'Package output is empty.');
    stableAssert(substr($raw, 0, 8) === Format::MAGIC, 'Fixed opaque, version-independent marker is incorrect.');
    stableAssert(strlen(substr($raw, 0, Format::HEADER_BYTES)) === 253, 'Fixed header length changed.');
    stableAssert(substr($raw, 8, 1) === chr(Format::FLAG_RECOVERY_SLOT), 'Recovery flag is incorrect.');
    stableAssert(substr($raw, 9, 4) === "\x01\x01\x01\x01", 'Algorithm identifiers are not at the specified offsets.');

    $header = Format::parseHeader(substr($raw, 0, Format::HEADER_BYTES));
    stableAssert($header['package_id_hex'] === str_repeat('a', 48), 'Header package identifier does not match the requested identifier.');
    stableAssert($header['ops'] === Format::DEFAULT_KDF_OPS, 'KDF operations parameter is not the writer profile.');
    stableAssert($header['memory_bytes'] === Format::DEFAULT_KDF_MEM_BYTES, 'KDF memory parameter is not the writer profile.');
    stableAssert(strlen($header['core']) === Format::CORE_BYTES, 'Core header length is invalid.');
    stableAssert(substr($raw, 0, 8) === Format::MAGIC
        && substr($raw, 0, 8) !== 'SECURE-PKG-V14',
        'The stable package marker is not the fixed opaque, version-independent marker.');
    // Manifest field/entry keys are asserted exactly below; scanning encrypted ciphertext
    // for English words would make this test probabilistic because ciphertext is random.

    $reader = new StablePackageReader();

    // Immutable on-disk bytes from an earlier writer build must remain readable;
    // a same-process writer/reader round trip cannot by itself prove compatibility.
    $fixtureEncoded = trim((string) file_get_contents(__DIR__ . '/fixtures/stable-format-v1.spkg.b64'));
    $fixtureBytes = base64_decode($fixtureEncoded, true);
    stableAssert(is_string($fixtureBytes) && strlen($fixtureBytes) > Format::HEADER_BYTES,
        'Immutable stable-format fixture is missing or malformed.');
    $fixturePath = $root . DIRECTORY_SEPARATOR . 'stable-format-v1.spkg';
    stableAssert(file_put_contents($fixturePath, $fixtureBytes, LOCK_EX) === strlen($fixtureBytes),
        'Unable to materialize immutable stable-format fixture.');
    $fixtureDestination = $root . DIRECTORY_SEPARATOR . 'stable-format-v1-restore';
    $fixtureResult = $reader->restore($fixturePath, $fixtureDestination,
        'Golden!FixturePassword2026#', 'Golden#Pattern!92Secure');
    stableAssert($fixtureResult['package_id'] === str_repeat('2', 48) && $fixtureResult['files'] === 1,
        'Immutable stable-format fixture metadata changed.');
    stableAssert(file_get_contents($fixtureDestination . DIRECTORY_SEPARATOR . 'fixture.txt')
        === "Stable binary format golden fixture v1\n",
        'Immutable stable-format fixture plaintext changed.');

    // Header parsers must reject unsafe values before any Argon2id invocation.
    $headerMutations = [
        [0, ord($raw[0]) ^ 0x01, 'bad magic'],
        [8, 0x80, 'reserved flag'],
        [9, 0x02, 'unknown KDF id'],
        [10, 0x02, 'unknown AEAD id'],
        [11, 0x02, 'unknown stream id'],
        [12, 0x02, 'unknown hash id'],
        [16, 0x00, 'invalid KDF ops'],
        [20, 0x01, 'unaligned KDF memory'],
    ];
    foreach ($headerMutations as $index => [$offset, $value, $label]) {
        $casePath = $root . DIRECTORY_SEPARATOR . 'bad-header-field-' . $index . '.spkg';
        stableCopy($package, $casePath);
        $bytes = file_get_contents($casePath);
        $bytes[$offset] = chr($value);
        file_put_contents($casePath, $bytes, LOCK_EX);
        $badDestination = $root . DIRECTORY_SEPARATOR . 'bad-header-field-restore-' . $index;
        stableExpectFailure(fn() => $reader->restore($casePath, $badDestination, $password, $pattern),
            'Unsupported or unsafe header field was accepted: ' . $label);
        stableAssert(!file_exists($badDestination), 'Invalid header left output behind: ' . $label);
    }

    $zeroIdPackage = $root . DIRECTORY_SEPARATOR . 'zero-id.spkg';
    stableExpectFailure(fn() => (new StablePackageWriter())->build($source, $zeroIdPackage,
        $password, $pattern, str_repeat('0', 48), false), 'All-zero package identifier was accepted by the writer.');
    stableAssert(!file_exists($zeroIdPackage), 'All-zero package identifier produced an output file.');
    $restored = $reader->restore($package, $restore, $password, $pattern);
    stableAssert($restored['files'] === 3 && $restored['directories'] === 1, 'Round-trip statistics are incorrect.');
    foreach (['hello.txt', 'empty.bin', 'nested/binary.dat'] as $relative) {
        $expected = hash_file('sha256', $source . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
        $actual = hash_file('sha256', $restore . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
        stableAssert(is_string($expected) && is_string($actual) && hash_equals($expected, $actual), 'Round-trip mismatch: ' . $relative);
    }

    $recoveryDestination = $root . DIRECTORY_SEPARATOR . 'recovery-restore';
    $recovered = $reader->restore($package, $recoveryDestination, '', '', $build['recovery_key']);
    stableAssert($recovered['files'] === 3, 'Recovery-key restore failed.');
    stableAssert(hash_file('sha256', $source . '/nested/binary.dat') === hash_file('sha256', $recoveryDestination . '/nested/binary.dat'), 'Recovery restore content mismatch.');

    stableExpectFailure(fn() => $reader->restore($package, $root . DIRECTORY_SEPARATOR . 'wrong-recovery',
        '', '', str_repeat('A', 43)), 'Wrong recovery key was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'wrong-recovery'), 'Wrong recovery key left output behind.');
    stableExpectFailure(fn() => $reader->restore($package, $root . DIRECTORY_SEPARATOR . 'malformed-recovery',
        '', '', 'not a recovery key'), 'Malformed recovery key was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'malformed-recovery'), 'Malformed recovery key left output behind.');

    $existingDestination = $root . DIRECTORY_SEPARATOR . 'already-exists';
    mkdir($existingDestination, 0700);
    file_put_contents($existingDestination . DIRECTORY_SEPARATOR . 'sentinel.txt', 'keep-this-file');
    $sentinelHash = hash_file('sha256', $existingDestination . DIRECTORY_SEPARATOR . 'sentinel.txt');
    stableExpectFailure(fn() => $reader->restore($package, $existingDestination, $password, $pattern), 'Existing destination was accepted.');
    stableAssert(hash_equals((string) $sentinelHash, (string) hash_file('sha256', $existingDestination . DIRECTORY_SEPARATOR . 'sentinel.txt')), 'Existing destination was altered.');

    stableExpectFailure(fn() => $reader->restore($package, $root . DIRECTORY_SEPARATOR . 'wrong-password', $wrongPassword, $pattern), 'Wrong password was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'wrong-password'), 'Wrong password left a destination behind.');
    stableExpectFailure(fn() => $reader->restore($package, $root . DIRECTORY_SEPARATOR . 'wrong-pattern', $password, $wrongPattern), 'Wrong pattern was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'wrong-pattern'), 'Wrong pattern left a destination behind.');

    $tamperedHeader = $root . DIRECTORY_SEPARATOR . 'tampered-header.spkg';
    stableCopy($package, $tamperedHeader);
    $tampered = file_get_contents($tamperedHeader);
    $tampered[Format::HEADER_BYTES - 1] = chr(ord($tampered[Format::HEADER_BYTES - 1]) ^ 0x01);
    file_put_contents($tamperedHeader, $tampered, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($tamperedHeader, $root . DIRECTORY_SEPARATOR . 'bad-header-restore', $password, $pattern), 'Tampered header MAC was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-header-restore'), 'Tampered header left restored data behind.');

    // Mutating the unused recovery slot must still invalidate the authenticated header.
    $tamperedRecoverySlot = $root . DIRECTORY_SEPARATOR . 'tampered-recovery-slot.spkg';
    stableCopy($package, $tamperedRecoverySlot);
    $bytes = file_get_contents($tamperedRecoverySlot);
    $bytes[149] = chr(ord($bytes[149]) ^ 0x01);
    file_put_contents($tamperedRecoverySlot, $bytes, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($tamperedRecoverySlot, $root . DIRECTORY_SEPARATOR . 'bad-recovery-slot-restore', $password, $pattern), 'Tampered recovery slot was accepted with primary credentials.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-recovery-slot-restore'), 'Tampered recovery slot left restored data behind.');

    $unknownRecord = $root . DIRECTORY_SEPARATOR . 'unknown-record.spkg';
    stableCopy($package, $unknownRecord);
    $bytes = file_get_contents($unknownRecord);
    $bytes[Format::HEADER_BYTES] = chr(0x55);
    file_put_contents($unknownRecord, $bytes, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($unknownRecord, $root . DIRECTORY_SEPARATOR . 'unknown-record-restore', $password, $pattern), 'Unknown record type was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'unknown-record-restore'), 'Unknown record left output behind.');

    $invalidLength = $root . DIRECTORY_SEPARATOR . 'invalid-length.spkg';
    stableCopy($package, $invalidLength);
    $bytes = file_get_contents($invalidLength);
    $bytes = substr((string) $bytes, 0, Format::HEADER_BYTES + 1)
        . pack('N', 0xFFFFFFFF)
        . substr((string) $bytes, Format::HEADER_BYTES + Format::RECORD_HEADER_BYTES);
    file_put_contents($invalidLength, $bytes, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($invalidLength, $root . DIRECTORY_SEPARATOR . 'invalid-length-restore', $password, $pattern), 'Oversized record length was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'invalid-length-restore'), 'Invalid record length left output behind.');

    $tamperedFileStart = $root . DIRECTORY_SEPARATOR . 'tampered-file-start.spkg';
    stableCopy($package, $tamperedFileStart);
    stableMutateRecord($tamperedFileStart, Format::RECORD_FILE_START);
    stableExpectFailure(fn() => $reader->restore($tamperedFileStart, $root . DIRECTORY_SEPARATOR . 'bad-file-start-restore', $password, $pattern), 'Tampered file-start record was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-file-start-restore'), 'Tampered file-start record left output behind.');

    $wrongChunkSequence = $root . DIRECTORY_SEPARATOR . 'wrong-chunk-sequence.spkg';
    stableCopy($package, $wrongChunkSequence);
    $bytes = file_get_contents($wrongChunkSequence);
    // The first file-start record follows the header; its first chunk starts after the 48-byte body.
    $sequenceOffset = Format::HEADER_BYTES + Format::RECORD_HEADER_BYTES + 48 + Format::RECORD_HEADER_BYTES + 16;
    $bytes[$sequenceOffset + 3] = chr(ord($bytes[$sequenceOffset + 3]) ^ 0x01);
    file_put_contents($wrongChunkSequence, $bytes, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($wrongChunkSequence, $root . DIRECTORY_SEPARATOR . 'bad-sequence-restore', $password, $pattern), 'Out-of-order chunk sequence was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-sequence-restore'), 'Out-of-order chunk sequence left output behind.');

    $tamperedChunk = $root . DIRECTORY_SEPARATOR . 'tampered-chunk.spkg';
    stableCopy($package, $tamperedChunk);
    stableMutateRecord($tamperedChunk, Format::RECORD_FILE_CHUNK);
    stableExpectFailure(fn() => $reader->restore($tamperedChunk, $root . DIRECTORY_SEPARATOR . 'bad-chunk-restore', $password, $pattern), 'Tampered file chunk was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-chunk-restore'), 'Tampered chunk left restored data behind.');

    $tamperedManifest = $root . DIRECTORY_SEPARATOR . 'tampered-manifest.spkg';
    stableCopy($package, $tamperedManifest);
    stableMutateRecord($tamperedManifest, Format::RECORD_MANIFEST, true);
    stableExpectFailure(fn() => $reader->restore($tamperedManifest, $root . DIRECTORY_SEPARATOR . 'bad-manifest-restore', $password, $pattern), 'Tampered manifest was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'bad-manifest-restore'), 'Tampered manifest left restored data behind.');

    $truncated = $root . DIRECTORY_SEPARATOR . 'truncated.spkg';
    stableCopy($package, $truncated);
    $size = filesize($truncated);
    stableAssert(is_int($size) && $size > 10, 'Truncation fixture is invalid.');
    $bytes = file_get_contents($truncated);
    file_put_contents($truncated, substr((string) $bytes, 0, -10), LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($truncated, $root . DIRECTORY_SEPARATOR . 'truncated-restore', $password, $pattern), 'Truncated package was accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'truncated-restore'), 'Truncated package left restored data behind.');

    $trailing = $root . DIRECTORY_SEPARATOR . 'trailing.spkg';
    stableCopy($package, $trailing);
    file_put_contents($trailing, "unexpected-tail", FILE_APPEND | LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($trailing, $root . DIRECTORY_SEPARATOR . 'trailing-restore', $password, $pattern), 'Trailing bytes after manifest were accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'trailing-restore'), 'Trailing data left restored output behind.');

    $unsafeKdf = $root . DIRECTORY_SEPARATOR . 'unsafe-kdf.spkg';
    stableCopy($package, $unsafeKdf);
    $bytes = file_get_contents($unsafeKdf);
    // memory_bytes at offset 17 must be rejected before Argon2id runs.
    $bytes = substr((string) $bytes, 0, 17) . pack('N', Format::MAX_KDF_MEM_BYTES + 1024) . substr((string) $bytes, 21);
    file_put_contents($unsafeKdf, $bytes, LOCK_EX);
    stableExpectFailure(fn() => $reader->restore($unsafeKdf, $root . DIRECTORY_SEPARATOR . 'unsafe-kdf-restore', $password, $pattern), 'Out-of-range KDF parameters were accepted.');
    stableAssert(!file_exists($root . DIRECTORY_SEPARATOR . 'unsafe-kdf-restore'), 'Unsafe KDF header left output behind.');

    $manifestProbe = Format::decodeManifest(Format::encodeManifest([
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => Format::zeroId(), 'name' => 'only.bin', 'size' => 0, 'chunks' => 1],
    ]));
    stableAssert(array_keys($manifestProbe) === ['entries', 'file_count', 'directory_count', 'total_plain_bytes'], 'Stable manifest decoder exposed unexpected metadata fields.');
    stableAssert(array_keys($manifestProbe['entries'][0]) === ['type', 'id', 'id_hex', 'parent_id', 'parent_hex', 'name', 'size', 'chunks', 'path', 'depth'], 'Stable manifest entry contains unexpected version or schema fields.');
    foreach (['../escape', 'CON', 'trailing.', 'trailing ', "nul\0name", 'a/b', 'a\\b'] as $unsafeName) {
        stableExpectFailure(fn() => Format::assertName($unsafeName), 'Unsafe package name was accepted: ' . $unsafeName);
    }

    $dirA = random_bytes(16); $dirB = random_bytes(16); $fileId = random_bytes(16);
    $cycleManifest = Format::encodeManifest([
        ['type' => 1, 'id' => $dirA, 'parent_id' => $dirB, 'name' => 'alpha'],
        ['type' => 1, 'id' => $dirB, 'parent_id' => $dirA, 'name' => 'beta'],
        ['type' => 2, 'id' => $fileId, 'parent_id' => $dirA, 'name' => 'data.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($cycleManifest), 'Manifest directory cycle was accepted.');

    $duplicateId = random_bytes(16);
    $duplicateIdManifest = Format::encodeManifest([
        ['type' => 2, 'id' => $duplicateId, 'parent_id' => Format::zeroId(), 'name' => 'a.bin', 'size' => 0, 'chunks' => 1],
        ['type' => 2, 'id' => $duplicateId, 'parent_id' => Format::zeroId(), 'name' => 'b.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($duplicateIdManifest), 'Duplicate manifest entry IDs were accepted.');

    $missingParentManifest = Format::encodeManifest([
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => random_bytes(16), 'name' => 'missing-parent.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($missingParentManifest), 'Missing manifest parent was accepted.');

    $fileParentId = random_bytes(16);
    $fileAsParentManifest = Format::encodeManifest([
        ['type' => 2, 'id' => $fileParentId, 'parent_id' => Format::zeroId(), 'name' => 'file', 'size' => 0, 'chunks' => 1],
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => $fileParentId, 'name' => 'child.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($fileAsParentManifest), 'Regular file used as parent was accepted.');

    $unorderedManifest = Format::encodeManifest([
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => Format::zeroId(), 'name' => 'z.bin', 'size' => 0, 'chunks' => 1],
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => Format::zeroId(), 'name' => 'a.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($unorderedManifest), 'Noncanonical manifest path order was accepted.');

    $caseCollisionManifest = Format::encodeManifest([
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => Format::zeroId(), 'name' => 'A.bin', 'size' => 0, 'chunks' => 1],
        ['type' => 2, 'id' => random_bytes(16), 'parent_id' => Format::zeroId(), 'name' => 'a.bin', 'size' => 0, 'chunks' => 1],
    ]);
    stableExpectFailure(fn() => Format::decodeManifest($caseCollisionManifest), 'Case-colliding sibling names were accepted.');

    $existingPackagePath = $root . DIRECTORY_SEPARATOR . 'existing-package.spkg';
    file_put_contents($existingPackagePath, 'preserve-existing-package');
    $existingPackageHash = hash_file('sha256', $existingPackagePath);
    stableExpectFailure(fn() => (new StablePackageWriter())->build($source, $existingPackagePath,
        $password, $pattern, str_repeat('c', 48), false), 'Writer overwrote an existing package destination.');
    stableAssert(hash_equals((string) $existingPackageHash, (string) hash_file('sha256', $existingPackagePath))
        && file_get_contents($existingPackagePath) === 'preserve-existing-package',
        'Existing package destination was modified by a failed create.');

    $noRecoveryPackage = $root . DIRECTORY_SEPARATOR . 'no-recovery.spkg';
    $noRecovery = (new StablePackageWriter())->build($source, $noRecoveryPackage, $password, $pattern, str_repeat('b', 48), false);
    stableAssert($noRecovery['recovery_key'] === null, 'Disabled recovery key was returned.');
    $noRecoveryBytes = file_get_contents($noRecoveryPackage);
    stableAssert(strlen(substr((string) $noRecoveryBytes, 0, Format::HEADER_BYTES)) === Format::HEADER_BYTES, 'No-recovery header size changed.');
    stableAssert(substr((string) $noRecoveryBytes, 8, 1) === "\0", 'No-recovery flag is incorrect.');
    stableAssert(Format::isZeroBytes(substr((string) $noRecoveryBytes, 149, Format::SLOT_BYTES)), 'Disabled recovery slot is not all-zero.');
    $noRecoveryDestination = $root . DIRECTORY_SEPARATOR . 'no-recovery-restore';
    $noRecoveryRestored = $reader->restore($noRecoveryPackage, $noRecoveryDestination, $password, $pattern);
    stableAssert($noRecoveryRestored['files'] === 3, 'No-recovery package did not restore.');

    echo "Stable binary package round-trip and adversarial tests passed.\n";
} finally {
    $password = '';
    $pattern = '';
    $wrongPassword = '';
    $wrongPattern = '';
    stableRemoveTree($root);
}
