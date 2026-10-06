<?php
declare(strict_types=1);

namespace SecurePackage\Project;

final class ManifestBuilder
{
    private array $nodes = [];

    public function addDirectory(string $id, ?string $parentId, string $encryptedName): void
    {
        $this->nodes[] = [
            'id' => $id,
            'parent' => $parentId,
            'type' => 'dir',
            'name' => $encryptedName,
        ];
    }

    public function addFile(string $id, ?string $parentId, string $encryptedName, string $blobId, int $size): void
    {
        $this->nodes[] = [
            'id' => $id,
            'parent' => $parentId,
            'type' => 'file',
            'name' => $encryptedName,
            'blob' => $blobId,
            'size' => $size,
        ];
    }

    public function count(): int
    {
        return count($this->nodes);
    }

    public function toJson(): string
    {
        return json_encode([
            'version' => 3,
            'format' => 'SECURE-PKG-V3',
            'schema' => 1,
            'node_count' => count($this->nodes),
            'nodes' => $this->nodes,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
