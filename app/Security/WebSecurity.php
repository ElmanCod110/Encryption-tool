<?php
declare(strict_types=1);

namespace TCH\Security;

use RuntimeException;

final class WebSecurity
{
    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }

    public static function csrfToken(): string
    {
        self::startSession();
        if (!isset($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return (string) $_SESSION['csrf'];
    }

    public static function assertCsrf(?string $token): void
    {
        self::startSession();
        if ($token === null || !isset($_SESSION['csrf']) || !hash_equals((string) $_SESSION['csrf'], $token)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
    }

    public static function ownerToken(): string
    {
        self::startSession();
        if (!isset($_SESSION['owner_token'])) {
            $_SESSION['owner_token'] = bin2hex(random_bytes(32));
        }
        return (string) $_SESSION['owner_token'];
    }
}
