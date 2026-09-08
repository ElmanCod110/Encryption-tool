<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

final class CallbackArchivePasswordProvider implements ArchivePasswordProvider
{
    public function __construct(private readonly \Closure $callback) {}

    public function passwordFor(string $archivePath, int $depth): string
    {
        $password = ($this->callback)($archivePath, $depth);
        if (!is_string($password)) {
            throw new RuntimeException('Archive password provider must return a string.');
        }
        return $password;
    }
}
