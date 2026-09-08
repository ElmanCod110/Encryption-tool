<?php
declare(strict_types=1);

namespace TCH\Archive;

use RuntimeException;
use TCH\Storage\JobStore;
use ZipArchive;

final class ArchiveWorkflow
{
    public function __construct(
        private readonly JobStore $jobs,
        private readonly ArchivePolicy $policy
    ) {}

    public function initialize(string $uploadedZip): array
    {
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
            throw new RuntimeException('PHP Zip extension is required.');
        }
        $job = $this->jobs->create();
        $archiveId = bin2hex(random_bytes(16));
        $archivePath = $job['path'] . DIRECTORY_SEPARATOR . 'archives' . DIRECTORY_SEPARATOR . $archiveId . '.zip';
        if (!copy($uploadedZip, $archivePath)) {
            throw new RuntimeException('Unable to initialize archive job.');
        }
        $state = [
            'status' => 'awaiting_archive_password',
            'root_archive' => $archiveId,
            'pending' => [[
                'id' => $archiveId,
                'file' => 'archives/' . $archiveId . '.zip',
                'destination' => 'source',
                'display_name' => 'Root archive',
            ]],
            'completed' => [],
            'stats' => ['archives' => 0, 'files' => 0, 'bytes' => 0],
            'created_at' => time(),
        ];
        $this->jobs->writeState($job['id'], $state);
        return ['job_id' => $job['id'], 'state' => $this->publicState($state)];
    }

    public function process(string $jobId, string $archiveId, string $password): array
    {
        $state = $this->jobs->readState($jobId);
        $pendingIndex = null;
        foreach ($state['pending'] as $index => $entry) {
            if ((string) ($entry['id'] ?? '') === $archiveId) {
                $pendingIndex = $index;
                break;
            }
        }
        if ($pendingIndex === null) {
            throw new RuntimeException('Archive is not pending.');
        }
        if (strlen($password) > 4096 || str_contains($password, "\0")) {
            throw new RuntimeException('Invalid archive password.');
        }

        $jobPath = $this->jobs->path($jobId);
        $archivePath = $jobPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, (string) $state['pending'][$pendingIndex]['file']);
        $destination = $jobPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, (string) $state['pending'][$pendingIndex]['destination']);
        if (!is_file($archivePath)) {
            throw new RuntimeException('Archive does not exist.');
        }
        if (!is_dir($destination) && !mkdir($destination, 0700, true) && !is_dir($destination)) {
            throw new RuntimeException('Unable to create archive destination.');
        }

        $stage = $jobPath . DIRECTORY_SEPARATOR . 'temp' . DIRECTORY_SEPARATOR . $archiveId . '-' . bin2hex(random_bytes(6));
        if (!mkdir($stage, 0700, true)) {
            throw new RuntimeException('Unable to create archive staging area.');
        }

        $zip = new ZipArchive();
        $localFiles = 0;
        $localBytes = 0;
        $newArchives = [];
        try {
            if ($zip->open($archivePath) !== true) {
                throw new RuntimeException('Unable to open archive.');
            }
            $zip->setPassword($password);
            if ($zip->numFiles > $this->policy->maxEntries) {
                throw new RuntimeException('Archive entry limit exceeded.');
            }
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) throw new RuntimeException('Unable to inspect archive entry.');
                $name = str_replace('\\', '/', (string) ($stat['name'] ?? ''));
                $this->validateEntryPath($name);
                if (strlen($name) > $this->policy->maxPathLength) throw new RuntimeException('Archive path is too long.');
                if ($this->isSymbolicLink($zip, $i)) throw new RuntimeException('Symbolic links are not supported.');

                $isDir = str_ends_with($name, '/');
                $size = max(0, (int) ($stat['size'] ?? 0));
                if (!$isDir) {
                    if ($size > $this->policy->maxSingleFileBytes || (int) $state['stats']['bytes'] + $localBytes + $size > $this->policy->maxTotalUncompressedBytes) {
                        throw new RuntimeException('Archive extraction limit exceeded.');
                    }
                }
                $target = $stage . DIRECTORY_SEPARATOR . $name;
                if ($isDir) {
                    if (!mkdir($target, 0700, true) && !is_dir($target)) throw new RuntimeException('Unable to create archive directory.');
                    continue;
                }
                $parent = dirname($target);
                if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) throw new RuntimeException('Unable to create extraction directory.');
                if (file_exists($target)) throw new RuntimeException('Archive contains duplicate output paths.');
                $stream = $zip->getStream($name);
                if ($stream === false) throw new RuntimeException('Unable to open archive content.');
                $out = fopen($target, 'xb');
                if ($out === false) { fclose($stream); throw new RuntimeException('Unable to create extracted file.'); }
                try {
                    $copied = stream_copy_to_stream($stream, $out);
                    if ($copied === false) throw new RuntimeException('Unable to extract archive content.');
                } finally { fclose($stream); fclose($out); }
                $localFiles++;
                $localBytes += $copied;

                if ($this->looksLikeZip($target)) {
                    if (count($state['pending']) + count($newArchives) >= $this->policy->maxNestedArchives) throw new RuntimeException('Nested archive count limit exceeded.');
                    $childId = bin2hex(random_bytes(16));
                    $stored = $jobPath . DIRECTORY_SEPARATOR . 'archives' . DIRECTORY_SEPARATOR . $childId . '.zip';
                    if (!rename($target, $stored)) throw new RuntimeException('Unable to queue nested archive.');
                    $relativeParent = str_replace('\\', '/', substr(dirname($target), strlen($jobPath) + 1));
                    $withoutZip = preg_replace('/\.zip$/i', '', $name);
                    $childDestination = ($relativeParent === '' ? '' : $relativeParent . '/') . $withoutZip;
                    $absoluteChildDestination = $jobPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $childDestination);
                    if (!is_dir($absoluteChildDestination) && !mkdir($absoluteChildDestination, 0700, true) && !is_dir($absoluteChildDestination)) throw new RuntimeException('Unable to prepare nested archive destination.');
                    $newArchives[] = ['id' => $childId, 'file' => 'archives/' . $childId . '.zip', 'destination' => $childDestination, 'display_name' => $name];
                }
            }
            $zip->close();
            $this->mergeDirectory($stage, $destination);
            $state['stats']['archives']++;
            $state['stats']['files'] += $localFiles;
            $state['stats']['bytes'] += $localBytes;
            array_splice($state['pending'], $pendingIndex, 1);
            foreach ($newArchives as $child) $state['pending'][] = $child;
            $state['completed'][] = $archiveId;
            $state['status'] = empty($state['pending']) ? 'ready_to_build' : 'awaiting_archive_password';
            $this->jobs->writeState($jobId, $state);
            @unlink($archivePath);
            return $this->publicState($state);
        } catch (\Throwable $e) {
            try { $zip->close(); } catch (\Throwable) {}
            $this->removeDirectory($stage);
            throw new RuntimeException('Unable to extract archive. The supplied archive password may be invalid.', 0, $e);
        }
    }

    public function sourceDirectory(string $jobId): string
    {
        $state = $this->jobs->readState($jobId);
        if (($state['status'] ?? '') !== 'ready_to_build') {
            throw new RuntimeException('Archive extraction is not complete.');
        }
        return $this->jobs->path($jobId) . DIRECTORY_SEPARATOR . 'source';
    }

    public function publicState(array $state): array
    {
        return [
            'status' => $state['status'] ?? 'unknown',
            'pending' => array_map(static fn(array $entry): array => [
                'id' => $entry['id'],
                'display_name' => $entry['display_name'],
            ], $state['pending'] ?? []),
            'stats' => $state['stats'] ?? [],
        ];
    }

    private function mergeDirectory(string $source, string $target): void
    {
        if (!is_dir($target) && !mkdir($target, 0700, true) && !is_dir($target)) {
            throw new RuntimeException('Unable to create destination directory.');
        }
        $iterator = new \FilesystemIterator($source, \FilesystemIterator::SKIP_DOTS);
        foreach ($iterator as $item) {
            $destination = $target . DIRECTORY_SEPARATOR . $item->getFilename();
            if (file_exists($destination)) {
                throw new RuntimeException('Archive output path collision detected.');
            }
            if (!rename($item->getPathname(), $destination)) {
                throw new RuntimeException('Unable to finalize extracted content.');
            }
        }
    }

    private function validateEntryPath(string $path): void
    {
        if ($path === '' || str_starts_with($path, '/') || preg_match('/^[A-Za-z]:\//', $path) === 1 || str_contains($path, "\0")) {
            throw new RuntimeException('Archive contains an unsafe path.');
        }
        foreach (explode('/', $path) as $part) {
            if ($part === '.' || $part === '..') {
                throw new RuntimeException('Archive contains an unsafe path.');
            }
        }
    }

    private function isSymbolicLink(ZipArchive $zip, int $index): bool
    {
        $opsys = 0;
        $attributes = 0;
        if (method_exists($zip, 'getExternalAttributesIndex') && $zip->getExternalAttributesIndex($index, $opsys, $attributes, ZipArchive::FL_UNCHANGED) && $opsys === ZipArchive::OPSYS_UNIX) {
            return (($attributes >> 16) & 0xF000) === 0xA000;
        }
        return false;
    }

    private function looksLikeZip(string $path): bool
    {
        if (!is_file($path) || filesize($path) < 4) return false;
        $handle = fopen($path, 'rb');
        if ($handle === false) return false;
        $signature = fread($handle, 4);
        fclose($handle);
        return in_array($signature, ["PK\x03\x04", "PK\x05\x06", "PK\x07\x08"], true);
    }
}
