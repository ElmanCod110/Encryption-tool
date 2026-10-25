<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use SecurePackage\Security\ProjectNameRegistryInterface;
use SecurePackage\Security\Validator;
use Throwable;

/**
 * Creates the permanent single-file binary package for new application builds.
 * Legacy V14 packages remain readable through the legacy reader; this service
 * never creates or rewrites the legacy directory format.
 */
final class StablePackageService
{
    public function __construct(
        private readonly StablePackageWriter $writer,
        private readonly string $packageStorage,
        private readonly ?ProjectNameRegistryInterface $registry = null
    ) {
        if (!is_dir($this->packageStorage)
            && !@mkdir($this->packageStorage, 0700, true)
            && !is_dir($this->packageStorage)) {
            throw new RuntimeException('Unable to initialize package storage.');
        }
        if (is_link($this->packageStorage)) {
            throw new RuntimeException('Package storage must not be a symbolic link.');
        }
    }

    public function build(
        string $sourceDir,
        string $projectName,
        string $password,
        string $pattern,
        bool $createRecovery = true
    ): array {
        Validator::validateProjectName($projectName);
        Validator::validatePassword($password);
        Validator::validatePattern($pattern);
        if ($this->registry !== null) {
            $this->registry->reserve($projectName);
        }

        $packageId = PackageId::generate();
        $packageFile = rtrim($this->packageStorage, DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . $packageId . '.spkg';

        try {
            $stats = $this->writer->build(
                $sourceDir,
                $packageFile,
                $password,
                $pattern,
                $packageId,
                $createRecovery
            );
            return [
                'package_id' => $packageId,
                'package_file' => $packageFile,
                'project_name' => $projectName,
                'stats' => $stats,
                'recovery_key' => $stats['recovery_key'] ?? null,
            ];
        } catch (Throwable $e) {
            // StablePackageWriter owns cleanup of its private partial file. Never
            // delete a pre-existing destination from this service's error path.
            throw $e;
        } finally {
            sodium_memzero($password);
            sodium_memzero($pattern);
        }
    }
}
