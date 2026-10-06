<?php
declare(strict_types=1);

namespace SecurePackage\Api;

use RuntimeException;

final class Request
{
    public static function json(int $maxBytes = 2_097_152): array
    {
        if ($maxBytes < 1) {
            throw new RuntimeException('Invalid request size policy.');
        }
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : null;
        if ($contentLength !== null && $contentLength > $maxBytes) {
            throw new RuntimeException('Request body is too large.');
        }
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
        }
        if (strlen($raw) > $maxBytes) {
            throw new RuntimeException('Request body is too large.');
        }
        try {
            $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new RuntimeException('Invalid JSON request.');
        }
        if (!is_array($data)) {
            throw new RuntimeException('Invalid JSON request.');
        }
        return $data;
    }
}
