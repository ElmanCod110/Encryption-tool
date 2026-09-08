<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;
use SecurePackage\Project\PackageCatalog;

/**
 * Centralizes authorization decisions for management actions.
 */
final class AuthorizationService
{
    public function requireAuthenticated(): string
    {
        $accountId = AccessContext::accountId();
        if ($accountId === null) {
            throw new RuntimeException('Authentication required.');
        }
        return $accountId;
    }

    public function requirePackageOwner(PackageCatalog $catalog, string $packageId): array
    {
        $owner = AccessContext::ownerId();
        return $catalog->assertOwner($packageId, $owner);
    }
}
