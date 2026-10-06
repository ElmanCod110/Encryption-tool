<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class ChunkStore
{
    public function __construct(private readonly string $root, private readonly int $maxChunkBytes = 16 * 1024 * 1024)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) throw new RuntimeException('Unable to initialize chunk storage.');
    }

    public function put(string $id, string $ciphertext): bool
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $id)) throw new RuntimeException('Invalid chunk identifier.');
        if ($ciphertext === '' || strlen($ciphertext) > $this->maxChunkBytes) throw new RuntimeException('Invalid chunk size.');
        $actual = hash('sha256', $ciphertext);
        if (!hash_equals($id, $actual)) throw new RuntimeException('Chunk digest mismatch.');
        $path = $this->path($id);
        if (is_file($path)) return false;
        $tmp = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        AtomicFile::write($tmp, $ciphertext);
        if (!@rename($tmp, $path)) { @unlink($tmp); throw new RuntimeException('Unable to commit chunk.'); }
        @chmod($path, 0600);
        return true;
    }

    public function has(string $id): bool { return preg_match('/^[a-f0-9]{64}$/', $id) === 1 && is_file($this->path($id)); }
    public function delete(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $id)) throw new RuntimeException('Invalid chunk identifier.');
        @unlink($this->path($id));
    }
    public function get(string $id): string
    {
        if (!$this->has($id)) throw new RuntimeException('Chunk does not exist.');
        $data = (string) file_get_contents($this->path($id));
        if (!hash_equals($id, hash('sha256', $data))) throw new RuntimeException('Stored chunk failed integrity verification.');
        return $data;
    }
    private function path(string $id): string { return $this->root . DIRECTORY_SEPARATOR . $id . '.bin'; }
}
