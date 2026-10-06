<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

/**
 * Scalable resumable upload inventory using one marker file per received chunk.
 * This avoids O(n) append-log scans when a large upload resumes.
 */
final class ResumableUploadV12
{
    public function __construct(
        private readonly string $root,
        private readonly int $ttlSeconds = 7200,
        private readonly int $maxChunks = 10_000_000,
        private readonly int $maxBytes = 4_294_967_296
    ) {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize upload storage.');
        }
    }

    public function create(string $ownerBinding, string $packageId, int $expectedChunks, int $expectedBytes, string $format = 'SECURE-BROWSER-V12'): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId) || $ownerBinding === '') throw new RuntimeException('Invalid upload declaration.');
        if ($expectedChunks < 1 || $expectedChunks > $this->maxChunks || $expectedBytes < 1 || $expectedBytes > $this->maxBytes) throw new RuntimeException('Invalid upload declaration.');
        $id = bin2hex(random_bytes(24));
        $dir = $this->dir($id);
        if (!mkdir($dir . '/received', 0700, true)) throw new RuntimeException('Unable to create upload session.');
        AtomicFile::write($dir . '/state.json', json_encode([
            'id' => $id,
            'format' => $format,
            'owner_hash' => hash('sha256', $ownerBinding),
            'package_id' => $packageId,
            'expected_chunks' => $expectedChunks,
            'expected_bytes' => $expectedBytes,
            'received_chunks' => 0,
            'received_bytes' => 0,
            'created_at' => time(),
            'finalized' => false,
        ], JSON_THROW_ON_ERROR));
        touch($dir . '/lock');
        return $this->state($id, $ownerBinding);
    }

    public function state(string $id, string $ownerBinding): array
    {
        $this->assertId($id);
        $path = $this->dir($id) . '/state.json';
        if (!is_file($path)) throw new RuntimeException('Upload does not exist.');
        $state = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
        if (!hash_equals((string) ($state['owner_hash'] ?? ''), hash('sha256', $ownerBinding))) throw new RuntimeException('Upload does not exist.');
        if (time() - (int) ($state['created_at'] ?? 0) > $this->ttlSeconds) throw new RuntimeException('Upload expired.');
        return $state;
    }

    public function addChunk(string $id, string $ownerBinding, string $chunkId, string $ciphertext): array
    {
        $this->assertId($id);
        if (!preg_match('/^[a-f0-9]{64}$/', $chunkId) || $ciphertext === '') throw new RuntimeException('Invalid encrypted chunk.');
        $size = strlen($ciphertext);
        if ($size > 8 * 1024 * 1024 + 64) throw new RuntimeException('Encrypted chunk is too large.');
        if (!hash_equals($chunkId, hash('sha256', $ciphertext))) throw new RuntimeException('Chunk digest mismatch.');
        $dir = $this->dir($id);
        $lock = @fopen($dir . '/lock', 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock upload.');
        try {
            $state = $this->state($id, $ownerBinding);
            if (($state['finalized'] ?? false) === true) throw new RuntimeException('Upload already finalized.');
            if ($state['received_bytes'] + $size > $state['expected_bytes']) throw new RuntimeException('Upload exceeds declared size.');
            $marker = $dir . '/received/' . $chunkId . '.json';
            if (!is_file($marker)) {
                if ($state['received_chunks'] + 1 > $state['expected_chunks']) throw new RuntimeException('Upload exceeds declared chunk count.');
                AtomicFile::write($marker, json_encode(['id' => $chunkId, 'bytes' => $size], JSON_THROW_ON_ERROR));
                $state['received_chunks']++;
                $state['received_bytes'] += $size;
                AtomicFile::write($dir . '/state.json', json_encode($state, JSON_THROW_ON_ERROR));
            }
            return $state;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function hasChunk(string $id, string $ownerBinding, string $chunkId): bool
    {
        $this->assertId($id);
        if (!preg_match('/^[a-f0-9]{64}$/', $chunkId)) return false;
        $this->state($id, $ownerBinding);
        return is_file($this->dir($id) . '/received/' . $chunkId . '.json');
    }

    public function inventory(string $id, string $ownerBinding): array
    {
        $state = $this->state($id, $ownerBinding);
        $entries = scandir($this->dir($id) . '/received');
        $chunks = [];
        foreach (($entries ?: []) as $entry) {
            if (preg_match('/^([a-f0-9]{64})\.json$/', $entry, $m)) $chunks[] = $m[1];
        }
        sort($chunks, SORT_STRING);
        return ['state' => $state, 'chunks' => $chunks];
    }

    public function finalize(string $id, string $ownerBinding): array
    {
        $dir = $this->dir($id);
        $lock = @fopen($dir . '/lock', 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock upload.');
        try {
            $state = $this->state($id, $ownerBinding);
            if (($state['received_chunks'] ?? 0) !== ($state['expected_chunks'] ?? -1) || ($state['received_bytes'] ?? 0) !== ($state['expected_bytes'] ?? -1)) throw new RuntimeException('Upload inventory is incomplete.');
            $state['finalized'] = true;
            $state['finalized_at'] = time();
            AtomicFile::write($dir . '/state.json', json_encode($state, JSON_THROW_ON_ERROR));
            return $state;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function delete(string $id, string $ownerBinding): void
    {
        $this->state($id, $ownerBinding);
        $dir = $this->dir($id);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $file) $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
        @rmdir($dir);
    }

    private function dir(string $id): string { return $this->root . DIRECTORY_SEPARATOR . $id; }
    private function assertId(string $id): void { if (!preg_match('/^[a-f0-9]{48}$/', $id)) throw new RuntimeException('Upload does not exist.'); }
}
