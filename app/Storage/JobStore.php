<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Throwable;

final class JobStore
{
    private const MAX_STATE_BYTES = 32768;

    public function __construct(private readonly string $root)
    {
        if (is_link($root)) {
            throw new RuntimeException('Job storage root must not be a symlink.');
        }
        if (!is_dir($root) && !@mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize job storage.');
        }
        $this->directoryIdentity($root);
        if (!@chmod($root, 0700)) {
            throw new RuntimeException('Unable to protect job storage.');
        }
    }

    public function create(?string $ownerToken = null): array
    {
        do {
            $id = bin2hex(random_bytes(24));
            $path = $this->root . DIRECTORY_SEPARATOR . $id;
        } while (file_exists($path) || is_link($path));

        if (!@mkdir($path, 0700, false)) {
            throw new RuntimeException('Unable to create job.');
        }
        $identity = $this->directoryIdentity($path);

        try {
            foreach (['source', 'archives'] as $child) {
                $childPath = $path . DIRECTORY_SEPARATOR . $child;
                if (!@mkdir($childPath, 0700, false)) {
                    throw new RuntimeException('Unable to initialize job directories.');
                }
                $this->directoryIdentity($childPath);
                if (!@chmod($childPath, 0700)) {
                    throw new RuntimeException('Unable to protect job directories.');
                }
            }
            $this->writeState($id, [
                'status' => 'created',
                'created_at' => time(),
                'owner_hash' => $ownerToken !== null ? hash('sha256', $ownerToken) : null,
            ]);
            $this->assertDirectoryIdentity($path, $identity);
            return ['id' => $id, 'path' => $path];
        } catch (Throwable $exception) {
            try {
                $this->removeOwnedDirectory($path, $identity);
            } catch (Throwable $cleanupError) {
                throw new RuntimeException('Unable to clean incomplete job initialization.', 0, $cleanupError);
            }
            throw $exception;
        }
    }

    public function path(string $id): string
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
            throw new JobNotAvailableException();
        }
        $path = $this->root . DIRECTORY_SEPARATOR . $id;
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat)) {
            if (!file_exists($path) && !is_link($path)) throw new JobNotAvailableException();
            throw new RuntimeException('Unable to inspect job directory.');
        }
        if (is_link($path) || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Job path is not a regular directory.');
        }
        return $path;
    }

    /**
     * Remove a validated job without following symlinks and only while the
     * identity of its owned root directory remains unchanged.
     */
    public function remove(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
            throw new RuntimeException('Invalid job identifier.');
        }
        $path = $this->root . DIRECTORY_SEPARATOR . $id;
        clearstatcache(true, $path);
        $rootStat = @lstat($path);
        if (!is_array($rootStat)) {
            if (file_exists($path) || is_link($path)) {
                throw new RuntimeException('Unable to inspect job cleanup target.');
            }
            return;
        }
        if (is_link($path) || (((int) ($rootStat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Job cleanup target is not an owned directory.');
        }
        $identity = ['dev' => (int) ($rootStat['dev'] ?? -1), 'ino' => (int) ($rootStat['ino'] ?? 0)];

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                $this->assertDirectoryIdentity($path, $identity);
                $itemPath = $item->getPathname();
                clearstatcache(true, $itemPath);
                $itemStat = @lstat($itemPath);
                if (!is_array($itemStat)) {
                    if (file_exists($itemPath) || is_link($itemPath)) {
                        throw new RuntimeException('Unable to inspect job cleanup entry.');
                    }
                    continue;
                }

                $itemMode = ((int) ($itemStat['mode'] ?? 0)) & 0170000;
                if ($itemMode === 0040000 && !is_link($itemPath)) {
                    if (!@rmdir($itemPath) && is_dir($itemPath)) {
                        throw new RuntimeException('Unable to remove job directory.');
                    }
                } else {
                    if (!@unlink($itemPath) && (file_exists($itemPath) || is_link($itemPath))) {
                        throw new RuntimeException('Unable to remove job file.');
                    }
                }
                clearstatcache(true, $itemPath);
                if (file_exists($itemPath) || is_link($itemPath)) {
                    throw new RuntimeException('Job cleanup entry remains after deletion.');
                }
            }
        } catch (Throwable $exception) {
            if ($exception instanceof RuntimeException) throw $exception;
            throw new RuntimeException('Unable to enumerate job cleanup entries.', 0, $exception);
        }

        $this->assertDirectoryIdentity($path, $identity);
        if (!@rmdir($path) && is_dir($path)) {
            throw new RuntimeException('Unable to remove job.');
        }
        clearstatcache(true, $path);
        if (file_exists($path) || is_link($path)) {
            throw new RuntimeException('Job directory remains after cleanup.');
        }
    }

    public function assertOwner(string $id, string $ownerToken): void
    {
        $state = $this->readState($id);
        $stored = (string) ($state['owner_hash'] ?? '');
        if ($stored === '' || !hash_equals($stored, hash('sha256', $ownerToken))) {
            throw new JobNotAvailableException();
        }
    }

    public function readState(string $id): array
    {
        $jobPath = $this->path($id);
        $path = $jobPath . DIRECTORY_SEPARATOR . 'state.json';
        $identity = $this->regularFileIdentity($path, false);
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            throw new RuntimeException('Unable to read job state.');
        }
        try {
            $handleStat = fstat($handle);
            if (!is_array($handleStat)
                || (((int) ($handleStat['mode'] ?? 0) & 0170000) !== 0100000)
                || (int) ($handleStat['dev'] ?? -2) !== $identity['dev']
                || (int) ($handleStat['ino'] ?? 0) !== $identity['ino']) {
                throw new RuntimeException('Job state identity changed while opening.');
            }
            $raw = stream_get_contents($handle, self::MAX_STATE_BYTES + 1);
            if ($raw === false) {
                throw new RuntimeException('Unable to read job state.');
            }
            if (strlen($raw) > self::MAX_STATE_BYTES) {
                throw new RuntimeException('Job state exceeds its size limit.');
            }
            $this->assertRegularFileIdentity($path, $identity, 'Job state identity changed while reading.');
        } finally {
            if (!fclose($handle)) {
                throw new RuntimeException('Unable to close job state.');
            }
        }

        try {
            $state = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Job state is corrupt.', 0, $exception);
        }
        if (!is_array($state)) {
            throw new RuntimeException('Job state is invalid.');
        }
        return $state;
    }

    public function writeState(string $id, array $state): void
    {
        $jobPath = $this->path($id);
        $jobIdentity = $this->directoryIdentity($jobPath);
        $path = $jobPath . DIRECTORY_SEPARATOR . 'state.json';

        clearstatcache(true, $path);
        $oldStat = @lstat($path);
        $oldIdentity = null;
        if (is_array($oldStat)) {
            if (is_link($path) || (((int) ($oldStat['mode'] ?? 0) & 0170000) !== 0100000)) {
                throw new RuntimeException('Job state is not a regular file.');
            }
            $oldIdentity = ['dev' => (int) ($oldStat['dev'] ?? -1), 'ino' => (int) ($oldStat['ino'] ?? 0)];
        } elseif (file_exists($path) || is_link($path)) {
            throw new RuntimeException('Unable to inspect existing job state.');
        }

        $json = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($json) > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Job state exceeds its size limit.');
        }
        $tmp = $path . '.partial.' . bin2hex(random_bytes(8));
        $handle = @fopen($tmp, 'x+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to create temporary job state.');
        }
        $tmpStat = fstat($handle);
        $tmpPathStat = @lstat($tmp);
        if (!is_array($tmpStat) || !is_array($tmpPathStat) || is_link($tmp)
            || (((int) ($tmpStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (((int) ($tmpPathStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($tmpStat['dev'] ?? -2) !== (int) ($tmpPathStat['dev'] ?? -1)
            || (int) ($tmpStat['ino'] ?? 0) !== (int) ($tmpPathStat['ino'] ?? -1)
            || (int) ($tmpStat['ino'] ?? 0) === 0) {
            fclose($handle);
            throw new RuntimeException('Temporary job state identity could not be verified.');
        }
        $tmpIdentity = ['dev' => (int) ($tmpStat['dev'] ?? -1), 'ino' => (int) $tmpStat['ino']];
        $published = false;

        try {
            if (!@chmod($tmp, 0600)) {
                throw new RuntimeException('Unable to protect temporary job state.');
            }
            self::writeAll($handle, $json);
            if (!fflush($handle)) {
                throw new RuntimeException('Unable to flush temporary job state.');
            }
            if (function_exists('fsync') && !fsync($handle)) {
                throw new RuntimeException('Unable to synchronize temporary job state.');
            }
            $this->assertDirectoryIdentity($jobPath, $jobIdentity);
            $this->assertRegularFileIdentity($tmp, $tmpIdentity, 'Temporary job state identity changed.');
            $this->assertStateDestinationIdentity($path, $oldIdentity);
            if (!fclose($handle)) {
                $handle = null;
                throw new RuntimeException('Unable to close temporary job state.');
            }
            $handle = null;

            // State updates intentionally replace the prior state, but only if it
            // is still the exact record observed before writing.
            $this->assertDirectoryIdentity($jobPath, $jobIdentity);
            $this->assertStateDestinationIdentity($path, $oldIdentity);
            if (!@rename($tmp, $path)) {
                throw new RuntimeException('Unable to commit job state.');
            }
            $published = true;
            $this->assertDirectoryIdentity($jobPath, $jobIdentity);
            $this->assertRegularFileIdentity($path, $tmpIdentity, 'Committed job state identity could not be verified.');
            if (!@chmod($path, 0600)) {
                throw new RuntimeException('Unable to protect committed job state.');
            }
        } catch (Throwable $exception) {
            if (is_resource($handle)) fclose($handle);
            if (!$published) {
                $this->removeOwnedFileIfPresent($tmp, $tmpIdentity);
            }
            throw $exception;
        }
    }

    private function directoryIdentity(string $path): array
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0040000)) {
            throw new RuntimeException('Storage path is not a regular directory.');
        }
        return ['dev' => (int) ($stat['dev'] ?? -1), 'ino' => (int) ($stat['ino'] ?? 0)];
    }

    private function assertDirectoryIdentity(string $path, array $expected): void
    {
        $actual = $this->directoryIdentity($path);
        if ($actual['dev'] !== (int) ($expected['dev'] ?? -1)
            || $actual['ino'] !== (int) ($expected['ino'] ?? -1)) {
            throw new RuntimeException('Job directory identity changed.');
        }
    }

    private function regularFileIdentity(string $path, bool $missingIsError): array
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)) {
            if (!$missingIsError && !file_exists($path) && !is_link($path)) {
                throw new RuntimeException('Job state does not exist.');
            }
            throw new RuntimeException('Job state is not a regular file.');
        }
        if ((int) ($stat['ino'] ?? 0) === 0) {
            throw new RuntimeException('Unable to verify job state identity.');
        }
        return ['dev' => (int) ($stat['dev'] ?? -1), 'ino' => (int) $stat['ino']];
    }

    private function assertRegularFileIdentity(string $path, array $expected, string $message): void
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($stat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)) {
            throw new RuntimeException($message);
        }
    }

    private function assertStateDestinationIdentity(string $path, ?array $expected): void
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if ($expected === null) {
            if (is_array($stat) || file_exists($path) || is_link($path)) {
                throw new RuntimeException('Job state destination appeared during creation.');
            }
            return;
        }
        if (!is_array($stat) || is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($stat['dev'] ?? -2) !== (int) ($expected['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($expected['ino'] ?? -1)) {
            throw new RuntimeException('Job state destination changed before commit.');
        }
    }

    private function removeOwnedDirectory(string $path, array $identity): void
    {
        $this->assertDirectoryIdentity($path, $identity);
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $this->assertDirectoryIdentity($path, $identity);
            $itemPath = $item->getPathname();
            $itemStat = @lstat($itemPath);
            if (!is_array($itemStat)) {
                if (file_exists($itemPath) || is_link($itemPath)) {
                    throw new RuntimeException('Unable to inspect incomplete job cleanup entry.');
                }
                continue;
            }
            if ((((int) ($itemStat['mode'] ?? 0) & 0170000) === 0040000) && !is_link($itemPath)) {
                if (!@rmdir($itemPath) && is_dir($itemPath)) {
                    throw new RuntimeException('Unable to remove incomplete job directory.');
                }
            } elseif (!@unlink($itemPath) && (file_exists($itemPath) || is_link($itemPath))) {
                throw new RuntimeException('Unable to remove incomplete job file.');
            }
            if (file_exists($itemPath) || is_link($itemPath)) {
                throw new RuntimeException('Incomplete job entry remains after cleanup.');
            }
        }
        $this->assertDirectoryIdentity($path, $identity);
        if (!@rmdir($path) && is_dir($path)) {
            throw new RuntimeException('Unable to remove incomplete job directory.');
        }
        if (file_exists($path) || is_link($path)) {
            throw new RuntimeException('Incomplete job directory remains after cleanup.');
        }
    }

    private function removeOwnedFileIfPresent(string $path, array $identity): void
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if (!is_array($stat)) {
            if (file_exists($path) || is_link($path)) {
                throw new RuntimeException('Unable to inspect temporary job state cleanup path.');
            }
            return;
        }
        if (is_link($path)
            || (((int) ($stat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($stat['dev'] ?? -2) !== (int) ($identity['dev'] ?? -1)
            || (int) ($stat['ino'] ?? 0) !== (int) ($identity['ino'] ?? -1)) {
            throw new RuntimeException('Temporary job state identity changed before cleanup.');
        }
        if (!@unlink($path) && (file_exists($path) || is_link($path))) {
            throw new RuntimeException('Unable to remove temporary job state.');
        }
        if (file_exists($path) || is_link($path)) {
            throw new RuntimeException('Temporary job state remains after cleanup.');
        }
    }

    private static function writeAll($handle, string $contents): void
    {
        $offset = 0;
        $length = strlen($contents);
        while ($offset < $length) {
            $written = fwrite($handle, substr($contents, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write job state.');
            }
            $offset += $written;
        }
    }

}
