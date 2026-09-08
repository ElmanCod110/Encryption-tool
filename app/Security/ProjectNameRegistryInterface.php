<?php
declare(strict_types=1);

namespace SecurePackage\Security;

interface ProjectNameRegistryInterface
{
    public function reserve(string $name): void;
}
