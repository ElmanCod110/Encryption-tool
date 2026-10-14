<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class ResumableUploadStore
{
    public function __construct(
        private readonly string $root,
        private readonly int $maxBytes,
        private readonly int $ttlSeconds = 3600,
        private readonly int $maxActiveUploadsPerOwner = 3,
        private readonly int $maxActiveBytesPerOwner = 1_099_511_627_776
    ) {
        if ($maxBytes < 1 || $ttlSeconds < 1 || $maxActiveUploadsPerOwner < 1 || $maxActiveBytesPerOwner < 1) {
            throw new RuntimeException('Invalid upload storage policy.');
        }
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize upload storage.');
        }
        @chmod($root, 0700);
    }

    public function initialize(int $totalBytes, string $ownerId, ?string $sha256 = null): array
    {
        if ($totalBytes <= 0 || $totalBytes > $this->maxBytes) throw new RuntimeException('Upload size is invalid.');
        if ($ownerId === '') throw new RuntimeException('Upload owner is invalid.');
        if ($sha256 !== null && !preg_match('/^[a-f0-9]{64}$/', $sha256)) throw new RuntimeException('Upload checksum is invalid.');

        $ownerHash = hash('sha256', $ownerId);
        $quotaLock = $this->acquireQuotaLock();
        try {
            $this->assertOwnerQuota($ownerHash, $totalBytes);
            do {
                $id = bin2hex(random_bytes(24));
                $dir = $this->directory($id);
            } while (file_exists($dir) || is_link($dir));

            if (!mkdir($dir, 0700, true)) throw new RuntimeException('Unable to create upload directory.');
            try {
                if (!touch($dir . DIRECTORY_SEPARATOR . 'upload.lock')) {
                    throw new RuntimeException('Unable to initialize upload lock.');
                }
                @chmod($dir . DIRECTORY_SEPARATOR . 'upload.lock', 0600);
                AtomicFile::write($dir . DIRECTORY_SEPARATOR . 'state.json', json_encode([
                    'id' => $id,
                    'total_bytes' => $totalBytes,
                    'received_bytes' => 0,
                    'created_at' => time(),
                    'owner_hash' => $ownerHash,
                    'sha256' => $sha256,
                ], JSON_THROW_ON_ERROR));
                $part = $dir . DIRECTORY_SEPARATOR . 'upload.part';
                $handle = @fopen($part, 'x+b');
                if ($handle === false) throw new RuntimeException('Unable to initialize upload data.');
                fclose($handle);
                @chmod($part, 0600);
                return ['id' => $id, 'received_bytes' => 0, 'total_bytes' => $totalBytes, 'sha256' => $sha256];
            } catch (\Throwable $exception) {
                $this->remove($id);
                throw $exception;
            }
        } finally {
            $this->releaseQuotaLock($quotaLock);
        }
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
        if (is_link($dir)) {
            @unlink($dir);
            return;
        }
        if (!is_dir($dir)) return;
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_link($file) || is_file($file)) {
                @unlink($file);
            } elseif (is_dir($file)) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($file, \FilesystemIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ($iterator as $item) {
                    $item->isLink() || !$item->isDir()
                        ? @unlink($item->getPathname())
                        : @rmdir($item->getPathname());
                }
                @rmdir($file);
            }
        }
        @rmdir($dir);
    }

    public function cleanup(): void
    {
        if (is_link($this->root) || !is_dir($this->root)) return;

        // Serialize cleanup with upload initialization, then lock each upload before
        // deciding whether it can be removed. Expired state is marked before unlinking
        // so a request that acquires the per-upload lock afterward fails closed.
        $quotaLock = $this->acquireQuotaLock();
        try {
            foreach (new \\FilesystemIterator($this->root, \\FilesystemIterator::SKIP_DOTS) as $entry) {
                $id = $entry->getFilename();
                if (!preg_match('/^[a-f0-9]{48}$/', $id)) continue;
                if ($entry->isLink()) {
                    @unlink($entry->getPathname());
                    continue;
                }
                if (!$entry->isDir()) continue;

                $directory = $entry->getPathname();
                $stateFile = $directory . DIRECTORY_SEPARATOR . 'state.json';
                $lockPath = $directory . DIRECTORY_SEPARATOR . 'upload.lock';
                $lock = @fopen($lockPath, 'c+b');
                if ($lock === false || !flock($lock, LOCK_EX)) {
                    if (is_resource($lock)) fclose($lock);
                    // A partial directory without a lock cannot be an active valid upload.
                    if (!is_file($stateFile)) $this->remove($id);
                    continue;
                }

                $remove = false;
                try {
                    $state = null;
                    if (is_link($stateFile) || !is_file($stateFile)) {
                        $remove = true;
                    } else {
                        try {
                            $state = json_decode((string) file_get_contents($stateFile), true, 16, JSON_THROW_ON_ERROR);
                        } catch (\\Throwable) {
                            $remove = true;
                        }
                        if (is_array($state)) {
                            $createdAt = (int) ($state['created_at'] ?? 0);
                            $remove = $createdAt <= 0 || time() - $createdAt > $this->ttlSeconds
                                || ($state['status'] ?? '') === 'expired';
                            if ($remove && $createdAt > 0) {
                                $state['status'] = 'expired';
                                AtomicFile::write($stateFile, json_encode($state, JSON_THROW_ON_ERROR));
                            }
                        }
                    }
                } finally {
                    flock($lock, LOCK_UN);
                    fclose($lock);
                }

                if ($remove) $this->remove($id);
            }
        } finally {
            $this->releaseQuotaLock($quotaLock);
        }
    }

    private function state(string $id): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) throw new RuntimeException('Invalid upload identifier.');
        $file = $this->directory($id) . DIRECTORY_SEPARATOR . 'state.json';
        if (!is_file($file)) throw new RuntimeException('Upload does not exist.');
        $state = json_decode((string) file_get_contents($file), true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($state)) throw new RuntimeException('Upload state is invalid.');
        if (($state['status'] ?? '') === 'expired' || (time() - (int) ($state['created_at'] ?? 0)) > $this->ttlSeconds) throw new RuntimeException('Upload has expired.');
        return $state;
    }

    private function assertOwner(array $state, string $ownerId): void
    {
        if (!hash_equals((string) ($state['owner_hash'] ?? ''), hash('sha256', $ownerId))) throw new RuntimeException('Upload does not exist.');
    }

    private function assertOwnerQuota(string $ownerHash, int $newBytes): void
    {
        $count = 0;
        $reservedBytes = 0;
        $now = time();

        foreach (new \FilesystemIterator($this->root, \FilesystemIterator::SKIP_DOTS) as $entry) {
            $id = $entry->getFilename();
            if (!preg_match('/^[a-f0-9]{48}$/', $id) || $entry->isLink() || !$entry->isDir()) continue;

            $statePath = $entry->getPathname() . DIRECTORY_SEPARATOR . 'state.json';
            if (is_link($statePath) || !is_file($statePath)) continue;
            $raw = @file_get_contents($statePath);
            if ($raw === false) throw new RuntimeException('Unable to verify active upload quota.');
            try {
                $state = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                throw new RuntimeException('Unable to verify active upload quota.');
            }
            if (!is_array($state)
                || !is_int($state['created_at'] ?? null)
                || !is_int($state['total_bytes'] ?? null)
                || $state['total_bytes'] < 1
                || $state['total_bytes'] > $this->maxBytes
                || !is_string($state['owner_hash'] ?? null)
                || !preg_match('/^[a-f0-9]{64}$/', $state['owner_hash'])) {
                throw new RuntimeException('Unable to verify active upload quota.');
            }
            if ($now - $state['created_at'] > $this->ttlSeconds) continue;
            if (hash_equals($state['owner_hash'], $ownerHash)) {
                $count++;
                $reservedBytes += max(0, $state['total_bytes']);
            }
        }

        if ($count >= $this->maxActiveUploadsPerOwner
            || $reservedBytes + $newBytes > $this->maxActiveBytesPerOwner) {
            throw new QuotaExceededException('Active upload quota exceeded.');
        }
    }

    private function acquireQuotaLock()
    {
        $path = $this->root . DIRECTORY_SEPARATOR . '.quota.lock';
        if (is_link($path)) throw new RuntimeException('Upload quota lock is invalid.');
        $handle = @fopen($path, 'c+b');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Unable to lock upload quota.');
        }
        @chmod($path, 0600);
        return $handle;
    }

    private function releaseQuotaLock($handle): void
    {
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    private function directory(string $id): string
    {
        return $this->root . DIRECTORY_SEPARATOR . $id;
    }
}
