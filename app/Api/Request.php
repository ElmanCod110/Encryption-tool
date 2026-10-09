<?php
declare(strict_types=1);

namespace SecurePackage\Api;

final class Request
{
    public static function json(int $maxBytes = 2_097_152): array
    {
        if ($maxBytes < 1) {
            throw new \LogicException('Invalid request size policy.');
        }

        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : null;
        if ($contentLength !== null && $contentLength > $maxBytes) {
            throw new HttpException(413, 'Request body is too large.');
        }

        $raw = file_get_contents('php://input');
        if ($raw === false) {
            throw new HttpException(400, 'Unable to read request body.');
        }
        if (strlen($raw) > $maxBytes) {
            throw new HttpException(413, 'Request body is too large.');
        }
        if ($raw === '') {
            return [];
        }

        try {
            $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new HttpException(400, 'Invalid JSON request.', $exception);
        }

        if (!is_array($data)) {
            throw new HttpException(400, 'Invalid JSON request.');
        }

        return $data;
    }
}
