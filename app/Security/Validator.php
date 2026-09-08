<?php
declare(strict_types=1);

namespace TCH\Security;

use InvalidArgumentException;

final class Validator
{
    public static function validatePassword(string $password): void
    {
        if (mb_strlen($password, 'UTF-8') < 12) {
            throw new InvalidArgumentException('Password must contain at least 12 characters.');
        }
        if (!preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password) || !preg_match('/\d/', $password) || !preg_match('/[^a-zA-Z0-9]/', $password)) {
            throw new InvalidArgumentException('Password must contain lowercase, uppercase, numeric, and special characters.');
        }
    }

    public static function validatePattern(string $pattern): void
    {
        if (mb_strlen($pattern, 'UTF-8') < 12) {
            throw new InvalidArgumentException('Pattern must contain at least 12 characters.');
        }
        if (preg_match('/^(.)\1+$/us', $pattern)) {
            throw new InvalidArgumentException('Pattern is too repetitive.');
        }
        $unique = count(array_unique(preg_split('//u', $pattern, -1, PREG_SPLIT_NO_EMPTY)));
        if ($unique < 5) {
            throw new InvalidArgumentException('Pattern does not contain enough character diversity.');
        }
    }

    public static function validateProjectName(string $name): void
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name, 'UTF-8') > 100) {
            throw new InvalidArgumentException('Project name is empty or too long.');
        }
        if (preg_match('/[\\\/\x00-\x1F\x7F]/u', $name)) {
            throw new InvalidArgumentException('Project name contains unsupported characters.');
        }
    }
}
