<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class WebSecurity
{
    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
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

    public static function applyHeaders(bool $html = false): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        if ($html) {
            header("Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
        }
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
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
