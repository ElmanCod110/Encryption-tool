<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use Closure;
use Throwable;

final class PackageDeletionTransaction
{
    private readonly Closure $rename;

    public function __construct(?callable $rename = null)
    {
        $this->rename = $rename === null
            ? static fn(string $from, string $to): bool => rename($from, $to)
            : Closure::fromCallable($rename);
    }

    /**
     * Stage all existing package representations before revoking access or deleting
     * the catalog record. Any pre-commit failure attempts a reverse-order rollback.
     *
     * @param list<string> $originalPaths
     * @return list<array{original: string, staged: string}>
     */
    public function execute(array $originalPaths, callable $revokeAccess, callable $deleteCatalog): array
    {
        $staged = [];

        try {
            foreach ($originalPaths as $originalPath) {
                if (!file_exists($originalPath) && !is_link($originalPath)) {
                    continue;
                }

                $stagedPath = $originalPath . '.deleting.' . bin2hex(random_bytes(12));
                if (!(($this->rename)($originalPath, $stagedPath))) {
                    throw new PackageStorageException('Unable to stage package deletion.');
                }
                $staged[] = ['original' => $originalPath, 'staged' => $stagedPath];
            }

            $revokeAccess();
            $deleteCatalog();

            return $staged;
        } catch (Throwable $exception) {
            foreach (array_reverse($staged) as $entry) {
                $stagedPath = $entry['staged'];
                $originalPath = $entry['original'];

                if (!file_exists($stagedPath) && !is_link($stagedPath)) {
                    continue;
                }
                if (file_exists($originalPath) || is_link($originalPath)) {
                    throw new PackageStorageException(
                        'Unable to roll back interrupted package deletion because the original path is occupied.',
                        0,
                        $exception
                    );
                }
                if (!(($this->rename)($stagedPath, $originalPath))) {
                    throw new PackageStorageException(
                        'Unable to roll back interrupted package deletion.',
                        0,
                        $exception
                    );
                }
            }

            throw $exception;
        }
    }

    /**
     * Remove staged artifacts after the catalog deletion has committed.
     *
     * @param list<array{original: string, staged: string}> $staged
     */
    public function cleanupCommitted(array $staged, callable $removePath): void
    {
        $cleanupException = null;

        foreach ($staged as $entry) {
            try {
                $removePath($entry['staged']);
                if (file_exists($entry['staged']) || is_link($entry['staged'])) {
                    throw new PackageStorageException('Unable to clean deleted package artifacts.');
                }
            } catch (Throwable $exception) {
                $cleanupException ??= $exception;
            }
        }

        if ($cleanupException !== null) {
            throw new PackageStorageException(
                'Unable to clean deleted package artifacts.',
                0,
                $cleanupException
            );
        }
    }
}
