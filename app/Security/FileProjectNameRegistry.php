<?php
declare(strict_types=1);

namespace TCH\Security;

use RuntimeException;

final class FileProjectNameRegistry
{
    public function __construct(private readonly string $file, private readonly string $serverPepper)
    {
        $parent = dirname($file);
        if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) {
            throw new RuntimeException('Unable to initialize project name registry.');
        }
        if (!is_file($file)) {
            file_put_contents($file, '', LOCK_EX);
            @chmod($file, 0600);
        }
    }

    public function reserve(string $name): void
    {
        Validator::validateProjectName($name);
        $hash = hash_hmac('sha256', $this->normalize($name), $this->serverPepper);
        $handle = fopen($this->file, 'c+');
        if ($handle === false) throw new RuntimeException('Unable to access project name registry.');
        try {
            if (!flock($handle, LOCK_EX)) throw new RuntimeException('Unable to lock project name registry.');
            rewind($handle);
            while (($line = fgets($handle)) !== false) {
                if (hash_equals(trim($line), $hash)) {
                    throw new RuntimeException('Project name is already reserved.');
                }
            }
            fseek($handle, 0, SEEK_END);
            if (fwrite($handle, $hash . PHP_EOL) === false) throw new RuntimeException('Unable to reserve project name.');
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
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
