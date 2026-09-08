<?php
declare(strict_types=1);

namespace TCH\Archive;

interface ArchivePasswordProvider
{
    public function passwordFor(string $archivePath, int $depth): string;
}
