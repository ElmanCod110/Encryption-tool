<?php
declare(strict_types=1);

namespace TCH\Storage;

use RuntimeException;

final class JobStore
{
    public function __construct(private readonly string $root)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize job storage.');
        }
    }

    public function create(?string $ownerToken = null): array
    {
        do {
            $id = bin2hex(random_bytes(24));
            $path = $this->root . DIRECTORY_SEPARATOR . $id;
        } while (file_exists($path));
        if (!mkdir($path, 0700, true)) {
            throw new RuntimeException('Unable to create job.');
        }
        mkdir($path . DIRECTORY_SEPARATOR . 'source', 0700, true);
        mkdir($path . DIRECTORY_SEPARATOR . 'archives', 0700, true);
        $this->writeState($id, ['status' => 'created', 'created_at' => time(), 'owner_hash' => $ownerToken !== null ? hash('sha256', $ownerToken) : null]);
        return ['id' => $id, 'path' => $path];
    }

    public function path(string $id): string
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
            throw new RuntimeException('Invalid job identifier.');
        }
        $path = $this->root . DIRECTORY_SEPARATOR . $id;
        if (!is_dir($path)) {
            throw new RuntimeException('Job does not exist.');
        }
        return $path;
    }

    public function assertOwner(string $id, string $ownerToken): void
    {
        $state = $this->readState($id);
        $stored = (string) ($state['owner_hash'] ?? '');
        if ($stored === '' || !hash_equals($stored, hash('sha256', $ownerToken))) {
            throw new RuntimeException('Job does not exist.');
        }
    }

    public function readState(string $id): array
    {
        $path = $this->path($id) . DIRECTORY_SEPARATOR . 'state.json';
        if (!is_file($path)) {
            throw new RuntimeException('Job state does not exist.');
        }
        $state = json_decode((string) file_get_contents($path), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($state)) {
            throw new RuntimeException('Invalid job state.');
        }
        return $state;
    }

    public function writeState(string $id, array $state): void
    {
        $path = $this->path($id) . DIRECTORY_SEPARATOR . 'state.json';
        $tmp = $path . '.partial.' . bin2hex(random_bytes(6));
        file_put_contents($tmp, json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), LOCK_EX);
        rename($tmp, $path);
        @chmod($path, 0600);
    }
}
