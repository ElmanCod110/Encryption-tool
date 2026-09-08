<?php
declare(strict_types=1);

namespace TCH\Security;

use PDO;
use RuntimeException;

final class ProjectNameRegistry
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $serverPepper
    ) {}

    public function reserve(string $name): void
    {
        Validator::validateProjectName($name);
        $normalized = $this->normalize($name);
        $hash = hash_hmac('sha256', $normalized, $this->serverPepper);
        try {
            $stmt = $this->pdo->prepare('INSERT INTO reserved_project_names (name_hash) VALUES (:name_hash)');
            $stmt->execute(['name_hash' => $hash]);
        } catch (\PDOException $e) {
            if ((int) $e->errorInfo[1] === 1062 || str_contains(strtolower($e->getMessage()), 'duplicate')) {
                throw new RuntimeException('Project name is already reserved.');
            }
            throw $e;
        }
    }

    private function normalize(string $name): string
    {
        $name = trim($name);
        if (class_exists('Normalizer')) {
            $name = \Normalizer::normalize($name, \Normalizer::FORM_C) ?: $name;
        }
        return mb_strtolower($name, 'UTF-8');
    }
}
