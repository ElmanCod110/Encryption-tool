<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Security\ProjectNameRegistryInterface;
use SecurePackage\Security\Validator;
use SecurePackage\Storage\FileStore;

final class V14PackageService
{
    public function __construct(
        private readonly V14PackageBuilder $builder,
        private readonly FileStore $store,
        private readonly ?ProjectNameRegistryInterface $registry = null
    ) {}

    public function build(string $sourceDir, string $projectName, string $password, string $pattern, bool $createRecovery = true): array
    {
        Validator::validateProjectName($projectName);
        Validator::validatePassword($password);
        Validator::validatePattern($pattern);
        if ($this->registry !== null) $this->registry->reserve($projectName);
        $packageId = PackageId::generate();
        $packageDir = $this->store->createPackageDirectory($packageId);
        try {
            $stats = $this->builder->build($sourceDir, $packageDir, $password, $pattern, $packageId, $createRecovery);
            return [
                'package_id' => $packageId,
                'package_dir' => $packageDir,
                'project_name' => $projectName,
                'stats' => $stats,
                'recovery_key' => $stats['recovery_key'] ?? null,
            ];
        } catch (\\Throwable $exception) {
            try {
                $this->removeDirectory($packageDir);
            } catch (\\Throwable $cleanupException) {
                throw new PackageStorageException('Unable to clean incomplete package build.', 0, $cleanupException);
            }
            throw $exception;
        } finally {
            sodium_memzero($password);
            sodium_memzero($pattern);
        }
    }

    private function removeDirectory(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            if (!unlink($path)) throw new PackageStorageException('Unable to remove incomplete package artifact.');
            return;
        }
        if (!is_dir($path)) return;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $itemPath = $item->getPathname();
            if ($item->isDir() && !$item->isLink()) {
                if (!rmdir($itemPath)) throw new PackageStorageException('Unable to remove incomplete package directory.');
            } elseif (!unlink($itemPath)) {
                throw new PackageStorageException('Unable to remove incomplete package file.');
            }
        }
        if (!rmdir($path)) throw new PackageStorageException('Unable to remove incomplete package directory.');
    }
}
