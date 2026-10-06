<?php
declare(strict_types=1);

namespace SecurePackage\Security;

final class AccessContext
{
    public static function ownerId(): string
    {
        WebSecurity::startSession();
        if (isset($_SESSION['account_id']) && is_string($_SESSION['account_id']) && preg_match('/^[a-f0-9]{32}$/', $_SESSION['account_id'])) {
            return 'account:' . $_SESSION['account_id'];
        }
        return 'session:' . WebSecurity::ownerToken();
    }

    public static function isAuthenticated(): bool
    {
        WebSecurity::startSession();
        return isset($_SESSION['account_id']) && is_string($_SESSION['account_id']) && preg_match('/^[a-f0-9]{32}$/', $_SESSION['account_id']) === 1;
    }

    public static function accountId(): ?string
    {
        return self::isAuthenticated() ? (string) $_SESSION['account_id'] : null;
    }
}
