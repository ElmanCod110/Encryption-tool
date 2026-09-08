<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class WebSecurity
{
    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) return;
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
        session_start();
    }

    public static function applyHeaders(bool $html = false): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('X-Permitted-Cross-Domain-Policies: none');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        if ($html) {
            header("Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; media-src 'none'; worker-src 'self'");
        }
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }

    public static function assertSameOrigin(): void
    {
        $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
        if ($origin === '') return;
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $expected = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? '');
        if (!hash_equals($expected, $origin)) throw new RuntimeException('Invalid request origin.');
    }

    public static function csrfToken(): string
    {
        self::startSession();
        if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
        return (string) $_SESSION['csrf'];
    }

    public static function rotateCsrf(): string
    {
        self::startSession();
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        return (string) $_SESSION['csrf'];
    }

    public static function assertCsrf(?string $token): void
    {
        self::startSession();
        if ($token === null || !isset($_SESSION['csrf']) || !hash_equals((string) $_SESSION['csrf'], $token)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
        self::assertSameOrigin();
    }

    public static function ownerToken(): string
    {
        self::startSession();
        if (!isset($_SESSION['owner_token'])) $_SESSION['owner_token'] = bin2hex(random_bytes(32));
        return (string) $_SESSION['owner_token'];
    }

    public static function login(string $accountId): void
    {
        self::startSession();
        session_regenerate_id(true);
        $_SESSION['account_id'] = $accountId;
        $_SESSION['owner_token'] = bin2hex(random_bytes(32));
        self::rotateCsrf();
    }

    public static function logout(): void
    {
        self::startSession();
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['owner_token'] = bin2hex(random_bytes(32));
        self::rotateCsrf();
    }
}
