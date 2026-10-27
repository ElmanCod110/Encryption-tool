<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use FilesystemIterator;
use RuntimeException;

final class PackageAccessTokenStore
{
    private const MAX_RECORD_BYTES = 16384;

    public function __construct(private readonly string $directory, private readonly int $ttlSeconds = 900)
    {
        if ($ttlSeconds < 1) {
            throw new RuntimeException('Invalid token lifetime policy.');
        }
        if (is_link($directory)) {
            throw new RuntimeException('Token storage directory must not be a symlink.');
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize token storage.');
        }
        clearstatcache(true, $directory);
        $stat = @lstat($directory);
        if (!is_array($stat) || is_link($directory)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Token storage directory is invalid.');
        }
        if (!@chmod($directory, 0700)) {
            throw new RuntimeException('Unable to protect token storage.');
        }
    }

    public function issue(string $packageId, string $ownerId, bool $oneTime = false): string
    {
        if ($packageId === '' || $ownerId === '') {
            throw new RuntimeException('Invalid access-token subject.');
        }

        $token = bin2hex(random_bytes(32));
        $file = $this->file($token);
        $now = time();
        $contents = json_encode([
            'package_id' => $packageId,
            'owner_id_hash' => hash('sha256', $ownerId),
            'created_at' => $now,
            'expires_at' => $now + $this->ttlSeconds,
            'one_time' => $oneTime,
        ], JSON_THROW_ON_ERROR);

        // This record is not visible to the caller until the complete write succeeds.
        // Exclusive-create prevents replacing a path that already exists.
        $handle = @fopen($file, 'x+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to create access token.');
        }
        $stat = fstat($handle);
        $pathStat = @lstat($file);
        if (!is_array($stat) || !is_array($pathStat) || is_link($file)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)
            || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($stat['ino'] ?? 0) === 0
            || (int) ($stat['dev'] ?? -2) !== (int) ($pathStat['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($pathStat['ino'] ?? -1)) {
            fclose($handle);
            // Do not unlink a path whose ownership cannot be established.
            throw new RuntimeException('Unable to verify access-token storage identity.');
        }
        $identity = ['dev' => (int) ($stat['dev'] ?? -1), 'ino' => (int) $stat['ino']];

        try {
            if (!@chmod($file, 0600)) {
                throw new RuntimeException('Unable to protect access-token record.');
            }
            $this->assertSameFileIdentity($file, $handle, $identity);
            self::writeAll($handle, $contents);
            if (!fflush($handle)) {
                throw new RuntimeException('Unable to flush access-token record.');
            }
            if (function_exists('fsync') && !fsync($handle)) {
                throw new RuntimeException('Unable to synchronize access-token record.');
            }
            $this->assertSameFileIdentity($file, $handle, $identity);
        } catch (\Throwable $exception) {
            fclose($handle);
            $this->removeOwnedFile($file, $identity);
            throw $exception;
        }

        if (!fclose($handle)) {
            $this->removeOwnedFile($file, $identity);
            throw new RuntimeException('Unable to close access-token record.');
        }
        return $token;
    }

    public function consume(string $token): array
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            throw new RuntimeException('Invalid or expired access token.');
        }

        $file = $this->file($token);
        $opened = $this->openLockedRecord($file, true);
        $handle = $opened['handle'];
        $identity = $opened['identity'];
        $removeAfterUnlock = false;

        try {
            $data = $this->readRecord($handle);
            if (!$this->isConsumedMarker($data)) {
                $this->assertTokenRecord($data);
                if ($data['expires_at'] <= time()) {
                    throw new RuntimeException('Invalid or expired access token.');
                }

                if ($data['one_time']) {
                    // A durable consumed marker prevents already-open waiters from replaying it.
                    $marker = json_encode(['consumed' => true], JSON_THROW_ON_ERROR);
                    $this->replaceLockedContents($handle, $marker);
                    $removeAfterUnlock = true;
                }
            } else {
                throw new RuntimeException('Invalid or expired access token.');
            }
        } finally {
            if (!flock($handle, LOCK_UN)) {
                fclose($handle);
                throw new RuntimeException('Unable to release access-token lock.');
            }
            if (!fclose($handle)) {
                throw new RuntimeException('Unable to close access-token record.');
            }
        }

        if ($removeAfterUnlock) {
            $this->removeOwnedFile($file, $identity);
        }
        return $data;
    }

    public function revokeForPackage(string $packageId): void
    {
        if ($packageId === '') {
            throw new RuntimeException('Invalid package identifier for token revocation.');
        }
        $rootStat = @lstat($this->directory);
        if (!is_array($rootStat) || is_link($this->directory)
            || (((int) ($rootStat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Token storage directory is unavailable.');
        }
        $rootIdentity = ['dev' => (int) ($rootStat['dev'] ?? -1), 'ino' => (int) ($rootStat['ino'] ?? 0)];

        try {
            $iterator = new FilesystemIterator($this->directory, FilesystemIterator::SKIP_DOTS);
            foreach ($iterator as $entry) {
                $name = $entry->getFilename();
                if (!str_ends_with($name, '.json')) {
                    continue;
                }
                if (!preg_match('/^[a-f0-9]{64}\.json$/D', $name)) {
                    throw new RuntimeException('Token storage contains an invalid record path.');
                }

                $this->assertDirectoryIdentity($this->directory, $rootIdentity);
                $file = $entry->getPathname();
                $opened = $this->openLockedRecord($file, false);
                $handle = $opened['handle'];
                $identity = $opened['identity'];
                $shouldRemove = false;
                try {
                    $data = $this->readRecord($handle);
                    if ($this->isConsumedMarker($data)) {
                        $shouldRemove = true;
                    } else {
                        $this->assertTokenRecord($data);
                        if (hash_equals($packageId, $data['package_id'])) {
                            $this->replaceLockedContents($handle, json_encode(['consumed' => true], JSON_THROW_ON_ERROR));
                            $shouldRemove = true;
                        }
                    }
                } finally {
                    if (!flock($handle, LOCK_UN)) {
                        fclose($handle);
                        throw new RuntimeException('Unable to release access-token lock during revocation.');
                    }
                    if (!fclose($handle)) {
                        throw new RuntimeException('Unable to close access-token record during revocation.');
                    }
                }

                if ($shouldRemove) {
                    $this->removeOwnedFile($file, $identity);
                }
            }
        } catch (\RuntimeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new RuntimeException('Unable to enumerate or revoke package access tokens.', 0, $exception);
        }
    }

    private function openLockedRecord(string $file, bool $missingIsInvalid): array
    {
        clearstatcache(true, $file);
        $pathStat = @lstat($file);
        if (!is_array($pathStat) || is_link($file)
            || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)) {
            throw new RuntimeException($missingIsInvalid
                ? 'Invalid or expired access token.'
                : 'Token storage contains an invalid record.');
        }

        $identity = ['dev' => (int) ($pathStat['dev'] ?? -1), 'ino' => (int) ($pathStat['ino'] ?? 0)];
        if ($identity['ino'] === 0) {
            throw new RuntimeException('Unable to verify access-token record identity.');
        }
        $handle = @fopen($file, 'r+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open access-token storage.');
        }
        $handleStat = fstat($handle);
        if (!is_array($handleStat)
            || (((int) ($handleStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($handleStat['dev'] ?? -2) !== $identity['dev']
            || (int) ($handleStat['ino'] ?? 0) !== $identity['ino']) {
            fclose($handle);
            throw new RuntimeException('Access-token path changed while opening.');
        }
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException('Unable to lock access-token storage.');
        }

        try {
            $this->assertSameFileIdentity($file, $handle, $identity);
        } catch (\Throwable $exception) {
            flock($handle, LOCK_UN);
            fclose($handle);
            throw $exception;
        }
        return ['handle' => $handle, 'identity' => $identity];
    }

    private function readRecord($handle): array
    {
        if (!rewind($handle)) {
            throw new RuntimeException('Unable to read access-token record.');
        }
        $raw = stream_get_contents($handle, self::MAX_RECORD_BYTES + 1);
        if ($raw === false) {
            throw new RuntimeException('Unable to read access-token record.');
        }
        if (strlen($raw) > self::MAX_RECORD_BYTES) {
            throw new RuntimeException('Access-token record exceeds the supported size.');
        }
        try {
            $data = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Access-token record is corrupt.', 0, $exception);
        }
        if (!is_array($data)) {
            throw new RuntimeException('Access-token record is invalid.');
        }
        return $data;
    }

    private function assertTokenRecord(array $data): void
    {
        if (!is_string($data['package_id'] ?? null)
            || $data['package_id'] === ''
            || !is_string($data['owner_id_hash'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $data['owner_id_hash'])
            || !is_int($data['created_at'] ?? null)
            || !is_int($data['expires_at'] ?? null)
            || !is_bool($data['one_time'] ?? null)
            || (isset($data['consumed']) && $data['consumed'] !== false)) {
            throw new RuntimeException('Access-token record is invalid.');
        }
    }

    private function isConsumedMarker(array $data): bool
    {
        return count($data) === 1 && ($data['consumed'] ?? null) === true;
    }

    private function replaceLockedContents($handle, string $contents): void
    {
        if (!rewind($handle) || !ftruncate($handle, 0)) {
            throw new RuntimeException('Unable to update access-token state.');
        }
        self::writeAll($handle, $contents);
        if (!fflush($handle)) {
            throw new RuntimeException('Unable to flush access-token state.');
        }
        if (function_exists('fsync') && !fsync($handle)) {
            throw new RuntimeException('Unable to synchronize access-token state.');
        }
    }

    private function assertSameFileIdentity(string $path, $handle, array $expected): void
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
            throw new RuntimeException('Access-token record identity changed.');
        }
    }

    private function assertDirectoryIdentity(string $path, array $expected): void
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0040000)
            || (int) ($stat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)) {
            throw new RuntimeException('Token storage directory identity changed.');
        }
    }

    private function removeOwnedFile(string $file, array $identity): void
    {
        clearstatcache(true, $file);
        $pathStat = @lstat($file);
        if (!is_array($pathStat)) {
            if (file_exists($file) || is_link($file)) {
                throw new RuntimeException('Unable to inspect access-token cleanup path.');
            }
            return;
        }
        if (is_link($file)
            || (((int) ($pathStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($pathStat['dev'] ?? -2) !== (int) ($identity['dev'] ?? -1)
            || (int) ($pathStat['ino'] ?? 0) !== (int) ($identity['ino'] ?? -1)) {
            throw new RuntimeException('Access-token cleanup path identity changed.');
        }
        if (!@unlink($file) && (file_exists($file) || is_link($file))) {
            throw new RuntimeException('Unable to remove access-token record.');
        }
        clearstatcache(true, $file);
        if (file_exists($file) || is_link($file)) {
            throw new RuntimeException('Access-token record remains after cleanup.');
        }
    }


    private static function writeAll($handle, string $contents): void
    {
        $offset = 0;
        $length = strlen($contents);
        while ($offset < $length) {
            $written = fwrite($handle, substr($contents, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write access-token record.');
            }
            $offset += $written;
        }
    }

    private function file(string $token): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    }
}
