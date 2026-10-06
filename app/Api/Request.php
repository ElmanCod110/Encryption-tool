<?php
declare(strict_types=1);

namespace SecurePackage\Api;

use RuntimeException;

final class Request
{
    public static function json(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
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
