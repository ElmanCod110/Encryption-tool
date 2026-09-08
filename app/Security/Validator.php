<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use InvalidArgumentException;

final class Validator
{
    public static function validatePassword(string $password): void
    {
        self::validateSecret($password, 'Password');
        if (self::length($password) < 12) {
            throw new InvalidArgumentException('Password must contain at least 12 characters.');
        }
        if (!preg_match('/[a-z]/u', $password) || !preg_match('/[A-Z]/u', $password) || !preg_match('/\d/u', $password) || !preg_match('/[^\p{L}\p{N}]/u', $password)) {
            throw new InvalidArgumentException('Password must contain lowercase, uppercase, numeric, and special characters.');
        }
        if (self::estimatedEntropy($password) < 60.0) {
            throw new InvalidArgumentException('Password entropy is too low.');
        }
    }

    public static function validatePattern(string $pattern): void
    {
        self::validateSecret($pattern, 'Pattern');
        if (self::length($pattern) < 12) {
            throw new InvalidArgumentException('Pattern must contain at least 12 characters.');
        }
        if (preg_match('/^(.)\1+$/us', $pattern)) {
            throw new InvalidArgumentException('Pattern is too repetitive.');
        }
        $chars = preg_split('//u', $pattern, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if (count(array_unique($chars)) < 5) {
            throw new InvalidArgumentException('Pattern does not contain enough character diversity.');
        }
        if (self::estimatedEntropy($pattern) < 50.0) {
            throw new InvalidArgumentException('Pattern entropy is too low.');
        }
    }

    public static function validateProjectName(string $name): void
    {
        $name = trim($name);
        if ($name === '' || self::length($name) > 100) {
            throw new InvalidArgumentException('Project name is empty or too long.');
        }
        if (preg_match('~[\\/\x00-\x1F\x7F]~u', $name)) {
            throw new InvalidArgumentException('Project name contains unsupported characters.');
        }
    }

    private static function length(string $value): int
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($value, 'UTF-8');
        }
        return preg_match_all('/./us', $value, $matches) ?: 0;
    }

    private static function validateSecret(string $value, string $label): void
    {
        if ($value === '' || strlen($value) > 4096 || str_contains($value, "\0")) {
            throw new InvalidArgumentException($label . ' is invalid.');
        }
        if (preg_match('//u', $value) !== 1) {
            throw new InvalidArgumentException($label . ' must be valid UTF-8.');
        }
    }

    private static function estimatedEntropy(string $secret): float
    {
        $pool = 0;
        if (preg_match('/[a-z]/u', $secret)) $pool += 26;
        if (preg_match('/[A-Z]/u', $secret)) $pool += 26;
        if (preg_match('/\d/u', $secret)) $pool += 10;
        if (preg_match('/[^\p{L}\p{N}]/u', $secret)) $pool += 33;
        $length = max(1, self::length($secret));
        return $length * log(max(2, $pool), 2);
    }
}
