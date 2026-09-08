<?php
declare(strict_types=1);

namespace TCH\Project;

final class ManifestBuilder
{
    private array $nodes = [];

    public function addDirectory(string $id, ?string $parentId, string $name): void
    {
        $this->nodes[] = ['id' => $id, 'parent' => $parentId, 'type' => 'dir', 'name' => $name];
    }

    public function addFile(string $id, ?string $parentId, string $name, string $blobId, int $size): void
    {
        $this->nodes[] = ['id' => $id, 'parent' => $parentId, 'type' => 'file', 'name' => $name, 'blob' => $blobId, 'size' => $size];
    }

    public function toJson(): string
    {
        return json_encode(['version' => 1, 'format' => 'TCH-PKG-V1', 'nodes' => $this->nodes], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}
