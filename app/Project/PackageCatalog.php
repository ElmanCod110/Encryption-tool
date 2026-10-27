<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class PackageCatalog
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize package catalog.');
        }
        @chmod($directory, 0700);
    }

    public function create(string $packageId, string $ownerId, string $name): array
    {
        if ($ownerId === '' || $name === '') {
            throw new RuntimeException('Invalid package catalog record.');
        }
        $file = $this->file($packageId);
        $lock = $this->acquireLock($packageId);
        try {
            if (is_link($file) || file_exists($file)) {
                throw new RuntimeException('Package catalog record already exists.');
            }
            $record = [
                'package_id' => $packageId,
                'owner_hash' => hash('sha256', $ownerId),
                'name_hash' => hash('sha256', $name),
                'created_at' => time(),
                'expires_at' => null,
                'revoked_at' => null,
            ];
            AtomicFile::write($file, json_encode($record, JSON_THROW_ON_ERROR));
            return $record;
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function get(string $packageId): array
    {
        $file = $this->file($packageId);
        if (is_link($file) || !is_file($file)) {
            throw new PackageNotAvailableException();
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            throw new RuntimeException('Package record is unavailable.');
        }
        try {
            $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new RuntimeException('Package record is invalid.');
        }
        if (!is_array($data)
            || ($data['package_id'] ?? null) !== $packageId
            || !is_string($data['owner_hash'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $data['owner_hash'])
            || !is_string($data['name_hash'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $data['name_hash'])
            || !is_int($data['created_at'] ?? null)
            || !(is_int($data['expires_at'] ?? null) || ($data['expires_at'] ?? null) === null)
            || !(is_int($data['revoked_at'] ?? null) || ($data['revoked_at'] ?? null) === null)) {
            throw new RuntimeException('Package record is invalid.');
        }
        return $data;
    }

    public function assertOwner(string $packageId, string $ownerId): array
    {
        $record = $this->get($packageId);
        if (!hash_equals((string) $record['owner_hash'], hash('sha256', $ownerId))) {
            throw new PackageNotAvailableException();
        }
        return $record;
    }


    public function assertAvailable(string $packageId): array
    {
        $record = $this->get($packageId);
        if (($record['revoked_at'] ?? null) !== null) throw new PackageNotAvailableException();
        if (($record['expires_at'] ?? null) !== null && (int) $record['expires_at'] <= time()) throw new PackageNotAvailableException();
        return $record;
    }

    public function delete(string $packageId, string $ownerId): void
    {
        $file = $this->file($packageId);
        $lock = $this->acquireLock($packageId);
        try {
            $this->assertOwner($packageId, $ownerId);
            if (!@unlink($file) && is_file($file)) {
                throw new RuntimeException('Unable to delete package record.');
            }
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function setExpiry(string $packageId, string $ownerId, ?int $expiresAt): void
    {
        $lock = $this->acquireLock($packageId);
        try {
            $record = $this->assertOwner($packageId, $ownerId);
            if ($expiresAt !== null && $expiresAt <= time()) {
                throw new RuntimeException('Expiration must be in the future.');
            }
            $record['expires_at'] = $expiresAt;
            AtomicFile::write($this->file($packageId), json_encode($record, JSON_THROW_ON_ERROR));
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function revoke(string $packageId, string $ownerId): void
    {
        $lock = $this->acquireLock($packageId);
        try {
            $record = $this->assertOwner($packageId, $ownerId);
            $record['revoked_at'] = time();
            AtomicFile::write($this->file($packageId), json_encode($record, JSON_THROW_ON_ERROR));
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function listForOwner(string $ownerId): array
    {
        $hash = hash('sha256', $ownerId);
        $items = [];

        try {
            $iterator = new \FilesystemIterator($this->directory, \FilesystemIterator::SKIP_DOTS);
            foreach ($iterator as $entry) {
                $fileName = $entry->getFilename();
                if (!str_ends_with($fileName, '.json')) continue;

                $packageId = substr($fileName, 0, -5);
                try {
                    PackageId::assert($packageId);
                } catch (RuntimeException $exception) {
                    throw new RuntimeException('Package catalog contains an invalid record path.', 0, $exception);
                }

                $file = $entry->getPathname();
                if ($entry->isLink() || !$entry->isFile() || is_link($file)) {
                    throw new RuntimeException('Package catalog contains a non-regular record.');
                }
                $raw = @file_get_contents($file);
                if ($raw === false) {
                    throw new RuntimeException('Unable to read package catalog record.');
                }
                try {
                    $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
                } catch (\JsonException $exception) {
                    throw new RuntimeException('Package catalog record is corrupt.', 0, $exception);
                }

                if (!is_array($data)
                    || ($data['package_id'] ?? null) !== $packageId
                    || !is_string($data['owner_hash'] ?? null)
                    || !preg_match('/^[a-f0-9]{64}$/', $data['owner_hash'])
                    || !is_string($data['name_hash'] ?? null)
                    || !preg_match('/^[a-f0-9]{64}$/', $data['name_hash'])
                    || !is_int($data['created_at'] ?? null)
                    || !(is_int($data['expires_at'] ?? null) || ($data['expires_at'] ?? null) === null)
                    || !(is_int($data['revoked_at'] ?? null) || ($data['revoked_at'] ?? null) === null)) {
                    throw new RuntimeException('Package catalog record is invalid.');
                }

                if (hash_equals($data['owner_hash'], $hash)) {
                    $items[] = $data;
                }
            }
        } catch (\RuntimeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new RuntimeException('Unable to enumerate package catalog.', 0, $exception);
        }

        usort($items, static fn(array $a, array $b): int => ((int) ($b['created_at'] ?? 0)) <=> ((int) ($a['created_at'] ?? 0)));
        return $items;
    }

    private function acquireLock(string $packageId)
    {
        $path = $this->file($packageId) . '.lock';
        if (is_link($path)) {
            throw new RuntimeException('Package catalog lock is invalid.');
        }
        $handle = @fopen($path, 'c+b');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Unable to lock package catalog record.');
        }
        @chmod($path, 0600);
        return $handle;
    }

    private function releaseLock($handle): void
    {
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    private function file(string $packageId): string
    {
        try {
            PackageId::assert($packageId);
        } catch (RuntimeException) {
            throw new PackageNotAvailableException();
        }
        return $this->directory . DIRECTORY_SEPARATOR . $packageId . '.json';
    }
}
