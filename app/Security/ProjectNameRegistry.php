<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use PDO;
use RuntimeException;

final class ProjectNameRegistry
{
    public function __construct(private readonly PDO $pdo, private readonly string $serverPepper) {}

    public function reserve(string $name): void
    {
        Validator::validateProjectName($name);
        $hash = hash_hmac('sha256', $this->normalize($name), $this->serverPepper);
        try {
            $stmt = $this->pdo->prepare('INSERT INTO reserved_project_names (name_hash) VALUES (:name_hash)');
            $stmt->execute(['name_hash' => $hash]);
        } catch (\PDOException $e) {
            if ((int) ($e->errorInfo[1] ?? 0) === 1062 || str_contains(strtolower($e->getMessage()), 'duplicate')) {
                throw new RuntimeException('Project name is already reserved.');
            }
            throw $e;
        }
    }

    public function hash(string $name): string
    {
        Validator::validateProjectName($name);
        return hash_hmac('sha256', $this->normalize($name), $this->serverPepper);
    }

    private function normalize(string $name): string
    {
        $name = trim($name);
        if (class_exists('Normalizer')) {
            $name = \Normalizer::normalize($name, \Normalizer::FORM_C) ?: $name;
        }
        return function_exists('mb_strtolower') ? mb_strtolower($name, 'UTF-8') : strtolower($name);
    }
}
