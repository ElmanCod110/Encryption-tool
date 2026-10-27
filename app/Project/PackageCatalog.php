<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class PackageCatalog
{
    public function __construct(private readonly string $directory)
    {
        if (is_link($directory)) {
            throw new RuntimeException('Package catalog directory must not be a symlink.');
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize package catalog.');
        }
        clearstatcache(true, $directory);
        $directoryStat = @lstat($directory);
        if (!is_array($directoryStat) || is_link($directory)
            || (((int) ($directoryStat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Package catalog directory is invalid.');
        }
        if (!@chmod($directory, 0700)) {
            throw new RuntimeException('Unable to protect package catalog directory.');
        }
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
        return $this->readRecordFile($this->file($packageId), $packageId, true);
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
            $identity = $this->regularFileIdentity($file, false);
            $this->assertPathIdentity($file, $identity, 'Package catalog record changed before deletion.');
            if (!@unlink($file) && (file_exists($file) || is_link($file))) {
                throw new PackageStorageException('Unable to delete package record.');
            }
            clearstatcache(true, $file);
            if (file_exists($file) || is_link($file)) {
                throw new PackageStorageException('Package catalog record remains after deletion.');
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
                $data = $this->readRecordFile($file, $packageId, false);

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
        clearstatcache(true, $path);
        if (is_link($path)) {
            throw new PackageStorageException('Package catalog lock is invalid.');
        }

        // Create the lock atomically when absent; otherwise open only a verified regular file.
        $handle = @fopen($path, 'x+b');
        if ($handle === false) {
            clearstatcache(true, $path);
            $before = @lstat($path);
            if (!is_array($before) || is_link($path)
                || (((int) ($before['mode'] ?? 0) & 0170000) !== 0100000)) {
                throw new PackageStorageException('Package catalog lock is invalid.');
            }
            $handle = @fopen($path, 'r+b');
            if ($handle === false) {
                throw new PackageStorageException('Unable to open package catalog lock.');
            }
            $expected = ['dev' => (int) ($before['dev'] ?? -1), 'ino' => (int) ($before['ino'] ?? 0)];
        } else {
            $created = fstat($handle);
            if (!is_array($created)
                || (((int) ($created['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($created['ino'] ?? 0) === 0) {
                fclose($handle);
                throw new PackageStorageException('Unable to verify new package catalog lock.');
            }
            $expected = ['dev' => (int) ($created['dev'] ?? -1), 'ino' => (int) $created['ino']];
        }

        try {
            $this->assertLockIdentity($path, $handle, $expected);
            if (!flock($handle, LOCK_EX)) {
                throw new PackageStorageException('Unable to lock package catalog record.');
            }
            $this->assertLockIdentity($path, $handle, $expected);
            if (!@chmod($path, 0600)) {
                throw new PackageStorageException('Unable to protect package catalog lock.');
            }
            return $handle;
        } catch (\Throwable $exception) {
            if (is_resource($handle)) {
                @flock($handle, LOCK_UN);
                fclose($handle);
            }
            throw $exception;
        }
    }
    private function releaseLock($handle): void
    {
        if (!flock($handle, LOCK_UN)) {
            fclose($handle);
            throw new PackageStorageException('Unable to release package catalog lock.');
        }
        if (!fclose($handle)) {
            throw new PackageStorageException('Unable to close package catalog lock.');
        }
    }

    private function readRecordFile(string $file, string $packageId, bool $missingIsUnavailable): array
    {
        clearstatcache(true, $file);
        $pathStat = @lstat($file);
        if (!is_array($pathStat) || is_link($file)
            || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)) {
            if ($missingIsUnavailable) {
                throw new PackageNotAvailableException();
            }
            throw new RuntimeException('Package catalog contains a non-regular record.');
        }
        $identity = ['dev' => (int) ($pathStat['dev'] ?? -1), 'ino' => (int) ($pathStat['ino'] ?? 0)];
        if ($identity['ino'] === 0) throw new RuntimeException('Unable to verify package catalog record identity.');

        $handle = @fopen($file, 'rb');
        if ($handle === false) throw new RuntimeException('Unable to read package catalog record.');
        try {
            $handleStat = fstat($handle);
            if (!is_array($handleStat)
                || (((int) ($handleStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($handleStat['dev'] ?? -2) !== $identity['dev']
                || (int) ($handleStat['ino'] ?? 0) !== $identity['ino']) {
                throw new RuntimeException('Package catalog record identity changed while opening.');
            }
            $raw = stream_get_contents($handle, 16385);
            if ($raw === false) throw new RuntimeException('Unable to read package catalog record.');
            if (strlen($raw) > 16384) throw new RuntimeException('Package catalog record exceeds its size limit.');
            $this->assertPathIdentity($file, $identity, 'Package catalog record identity changed while reading.');
        } finally {
            fclose($handle);
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
        return $data;
    }

    private function regularFileIdentity(string $path, bool $missingIsUnavailable): array
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)) {
            if ($missingIsUnavailable) throw new PackageNotAvailableException();
            throw new PackageStorageException('Package catalog record is unavailable for deletion.');
        }
        return ['dev' => (int) ($stat['dev'] ?? -1), 'ino' => (int) ($stat['ino'] ?? 0)];
    }

    private function assertPathIdentity(string $path, array $expected, string $message): void
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($stat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)) {
            throw new PackageStorageException($message);
        }
    }

    private function assertLockIdentity(string $path, $handle, array $expected): void
    {
        clearstatcache(true, $path);
        $pathStat = @lstat($path);
        $handleStat = fstat($handle);
        if (!is_array($pathStat) || !is_array($handleStat) || is_link($path)
            || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (((int) ($handleStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($pathStat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($pathStat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)
            || (int) ($handleStat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($handleStat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)) {
            throw new PackageStorageException('Package catalog lock identity changed.');
        }
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
