<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

interface ArchivePasswordProvider
{
    public function passwordFor(string $archivePath, int $depth): string;
}
