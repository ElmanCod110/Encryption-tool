<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class PackageCatalog
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize package catalog.');
        }
    }

    public function create(string $packageId, string $ownerId, string $name): array
    {
        $record = [
            'package_id' => $packageId,
            'owner_hash' => hash('sha256', $ownerId),
            'name_hash' => hash('sha256', $name),
            'created_at' => time(),
            'expires_at' => null,
            'revoked_at' => null,
        ];
        AtomicFile::write($this->file($packageId), json_encode($record, JSON_THROW_ON_ERROR));
        return $record;
    }

    public function get(string $packageId): array
    {
        $file = $this->file($packageId);
        if (!is_file($file)) {
            throw new RuntimeException('Package does not exist.');
        }
        $data = json_decode((string) file_get_contents($file), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new RuntimeException('Package record is invalid.');
        }
        return $data;
    }

    public function assertOwner(string $packageId, string $ownerId): array
    {
        $record = $this->get($packageId);
        if (!hash_equals((string) $record['owner_hash'], hash('sha256', $ownerId))) {
            throw new RuntimeException('Package does not exist.');
        }
        return $record;
    }


    public function assertAvailable(string $packageId): array
    {
        $record = $this->get($packageId);
        if (($record['revoked_at'] ?? null) !== null) throw new RuntimeException('Package is revoked.');
        if (($record['expires_at'] ?? null) !== null && (int) $record['expires_at'] <= time()) throw new RuntimeException('Package is expired.');
        return $record;
    }

    public function delete(string $packageId, string $ownerId): void
    {
        $this->assertOwner($packageId, $ownerId);
        $file = $this->file($packageId);
        if (!@unlink($file) && is_file($file)) throw new RuntimeException('Unable to delete package record.');
    }

    public function setExpiry(string $packageId, string $ownerId, ?int $expiresAt): void
    {
        $record = $this->assertOwner($packageId, $ownerId);
        if ($expiresAt !== null && $expiresAt <= time()) throw new RuntimeException('Expiration must be in the future.');
        $record['expires_at'] = $expiresAt;
        AtomicFile::write($this->file($packageId), json_encode($record, JSON_THROW_ON_ERROR));
    }

    public function revoke(string $packageId, string $ownerId): void
    {
        $record = $this->assertOwner($packageId, $ownerId);
        $record['revoked_at'] = time();
        AtomicFile::write($this->file($packageId), json_encode($record, JSON_THROW_ON_ERROR));
    }

    public function listForOwner(string $ownerId): array
    {
        $hash = hash('sha256', $ownerId);
        $items = [];
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            $data = json_decode((string) @file_get_contents($file), true);
            if (!is_array($data) || !hash_equals((string) ($data['owner_hash'] ?? ''), $hash)) {
                continue;
            }
            $items[] = $data;
        }
        usort($items, static fn(array $a, array $b): int => ((int) ($b['created_at'] ?? 0)) <=> ((int) ($a['created_at'] ?? 0)));
        return $items;
    }

    private function file(string $packageId): string
    {
        PackageId::assert($packageId);
        return $this->directory . DIRECTORY_SEPARATOR . $packageId . '.json';
    }
}
