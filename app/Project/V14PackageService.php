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
        } catch (\Throwable $e) {
            $this->removeDirectory($packageDir);
            throw $e;
        } finally {
            sodium_memzero($password);
            sodium_memzero($pattern);
        }
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) return;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \FilesystemIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($path);
    }
}
