<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class ResumableUploadStore
{
    public function __construct(private readonly string $root, private readonly int $maxBytes, private readonly int $ttlSeconds = 3600)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize upload storage.');
        }
    }

    public function initialize(int $totalBytes, string $ownerId, ?string $sha256 = null): array
    {
        if ($totalBytes <= 0 || $totalBytes > $this->maxBytes) throw new RuntimeException('Upload size is invalid.');
        if ($sha256 !== null && !preg_match('/^[a-f0-9]{64}$/', $sha256)) throw new RuntimeException('Upload checksum is invalid.');
        do {
            $id = bin2hex(random_bytes(24));
            $dir = $this->directory($id);
        } while (file_exists($dir));
        if (!mkdir($dir, 0700, true)) throw new RuntimeException('Unable to create upload directory.');
        touch($dir . DIRECTORY_SEPARATOR . 'upload.lock');
        AtomicFile::write($dir . DIRECTORY_SEPARATOR . 'state.json', json_encode([
            'id' => $id,
            'total_bytes' => $totalBytes,
            'received_bytes' => 0,
            'created_at' => time(),
            'owner_hash' => hash('sha256', $ownerId),
            'sha256' => $sha256,
        ], JSON_THROW_ON_ERROR));
        $part = $dir . DIRECTORY_SEPARATOR . 'upload.part';
        touch($part);
        @chmod($part, 0600);
        return ['id' => $id, 'received_bytes' => 0, 'total_bytes' => $totalBytes, 'sha256' => $sha256];
    }

    public function append(string $id, int $offset, string $chunk, string $ownerId): array
    {
        if ($chunk === '') throw new RuntimeException('Upload chunk is empty.');
        $lock = fopen($this->directory($id) . DIRECTORY_SEPARATOR . 'upload.lock', 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) fclose($lock);
            throw new RuntimeException('Unable to lock upload.');
        }
        try {
            $state = $this->state($id);
            $this->assertOwner($state, $ownerId);
            if ($offset !== (int) $state['received_bytes']) throw new RuntimeException('Unexpected upload offset.');
            $next = $offset + strlen($chunk);
            if ($next > (int) $state['total_bytes']) throw new RuntimeException('Upload exceeds declared size.');
            $path = $this->directory($id) . DIRECTORY_SEPARATOR . 'upload.part';
            $handle = fopen($path, 'ab');
            if ($handle === false) throw new RuntimeException('Unable to write upload chunk.');
            try {
                if (fwrite($handle, $chunk) !== strlen($chunk)) throw new RuntimeException('Unable to write upload chunk.');
                fflush($handle);
            } finally { fclose($handle); }
            $state['received_bytes'] = $next;
            AtomicFile::write($this->directory($id) . DIRECTORY_SEPARATOR . 'state.json', json_encode($state, JSON_THROW_ON_ERROR));
            return $state;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function finalize(string $id, string $ownerId): string
    {
        $lock = fopen($this->directory($id) . DIRECTORY_SEPARATOR . 'upload.lock', 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) fclose($lock);
            throw new RuntimeException('Unable to lock upload.');
        }
        try {
            $state = $this->state($id);
            $this->assertOwner($state, $ownerId);
            if ((int) $state['received_bytes'] !== (int) $state['total_bytes']) throw new RuntimeException('Upload is incomplete.');
            $source = $this->directory($id) . DIRECTORY_SEPARATOR . 'upload.part';
            $destination = $this->directory($id) . DIRECTORY_SEPARATOR . 'upload.zip';
            if (($state['sha256'] ?? null) !== null) {
                $actual = hash_file('sha256', $source);
                if (!is_string($actual) || !hash_equals((string) $state['sha256'], $actual)) throw new RuntimeException('Upload checksum verification failed.');
            }
            if (!rename($source, $destination)) throw new RuntimeException('Unable to finalize upload.');
            @chmod($destination, 0600);
            return $destination;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function remove(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) return;
        $dir = $this->directory($id);
        if (!is_dir($dir)) return;
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*') ?: [] as $file) @unlink($file);
        @rmdir($dir);
    }

    public function cleanup(): void
    {
        foreach (glob($this->root . DIRECTORY_SEPARATOR . '*') ?: [] as $dir) {
            if (!is_dir($dir)) continue;
            $stateFile = $dir . DIRECTORY_SEPARATOR . 'state.json';
            if (!is_file($stateFile) || (time() - (int) @filemtime($stateFile)) > $this->ttlSeconds) $this->remove(basename($dir));
        }
    }

    private function state(string $id): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) throw new RuntimeException('Invalid upload identifier.');
        $file = $this->directory($id) . DIRECTORY_SEPARATOR . 'state.json';
        if (!is_file($file)) throw new RuntimeException('Upload does not exist.');
        $state = json_decode((string) file_get_contents($file), true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($state)) throw new RuntimeException('Upload state is invalid.');
        if ((time() - (int) ($state['created_at'] ?? 0)) > $this->ttlSeconds) throw new RuntimeException('Upload has expired.');
        return $state;
    }

    private function assertOwner(array $state, string $ownerId): void
    {
        if (!hash_equals((string) ($state['owner_hash'] ?? ''), hash('sha256', $ownerId))) throw new RuntimeException('Upload does not exist.');
    }

    private function directory(string $id): string
    {
        return $this->root . DIRECTORY_SEPARATOR . $id;
    }
}
