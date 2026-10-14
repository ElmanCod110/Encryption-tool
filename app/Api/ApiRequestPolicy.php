<?php
declare(strict_types=1);

namespace SecurePackage\Api;

final class ApiRequestPolicy
{
    private const ACTIONS = [
        'me', 'register', 'login', 'logout', 'upload-init', 'upload-chunk',
        'upload-complete', 'archive-step', 'build', 'decrypt', 'packages',
        'access-token', 'set-expiry', 'revoke', 'delete', 'security-status', 'csrf',
    ];

    public static function assertAllowed(string $action, string $method, string $contentType): void
    {
        if (!in_array($action, self::ACTIONS, true)) {
            throw new HttpException(404, 'Unknown action.');
        }

        if (strtoupper($method) !== 'POST') {
            throw new HttpException(405, 'Method not allowed.');
        }

        $mediaType = strtolower(trim(explode(';', $contentType, 2)[0]));
        if ($action === 'csrf') {
            return;
        }

        $expected = $action === 'upload-chunk'
            ? 'application/octet-stream'
            : 'application/json';

        if ($mediaType !== $expected) {
            throw new HttpException(415, 'Unsupported media type.');
        }
    }
}
