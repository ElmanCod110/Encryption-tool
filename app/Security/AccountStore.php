<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class AccountStore
{
    public function __construct(private readonly string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to initialize account storage.');
        }
        if (!is_file($file)) {
            AtomicFile::write($file, "[]\n");
        }
    }

    public function register(string $username, string $password): string
    {
        $username = $this->normalizeUsername($username);
        Validator::validatePassword($password);
        $accounts = $this->read();
        foreach ($accounts as $account) {
            if (hash_equals((string) $account['username_hash'], $this->usernameHash($username))) {
                throw new RuntimeException('Account already exists.');
            }
        }
        $id = bin2hex(random_bytes(16));
        $accounts[] = [
            'id' => $id,
            'username_hash' => $this->usernameHash($username),
            'username_hint' => substr($username, 0, 2),
            'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
            'created_at' => time(),
        ];
        $this->write($accounts);
        return $id;
    }

    public function verify(string $username, string $password): ?string
    {
        $username = $this->normalizeUsername($username);
        foreach ($this->read() as $account) {
            if (!hash_equals((string) $account['username_hash'], $this->usernameHash($username))) {
                continue;
            }
            if (!password_verify($password, (string) $account['password_hash'])) {
                return null;
            }
            if (password_needs_rehash((string) $account['password_hash'], PASSWORD_ARGON2ID)) {
                $account['password_hash'] = password_hash($password, PASSWORD_ARGON2ID);
                $this->replace((string) $account['id'], $account);
            }
            return (string) $account['id'];
        }
        return null;
    }

    public function exists(string $id): bool
    {
        foreach ($this->read() as $account) {
            if (hash_equals((string) $account['id'], $id)) {
                return true;
            }
        }
        return false;
    }

    private function normalizeUsername(string $username): string
    {
        $username = trim($username);
        if ($username === '' || strlen($username) < 3 || strlen($username) > 80 || preg_match('/[^A-Za-z0-9_.@-]/', $username)) {
            throw new RuntimeException('Username is invalid.');
        }
        return strtolower($username);
    }

    private function usernameHash(string $username): string
    {
        $pepper = (string) (getenv('SPK_NAME_PEPPER') ?: '');
        if ($pepper === '') {
            throw new RuntimeException('SPK_NAME_PEPPER must be configured.');
        }
        return hash_hmac('sha256', $username, $pepper);
    }

    private function read(): array
    {
        $raw = file_get_contents($this->file);
        $data = json_decode((string) $raw, true);
        return is_array($data) ? $data : [];
    }

    private function write(array $accounts): void
    {
        AtomicFile::write($this->file, json_encode($accounts, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL);
    }

    private function replace(string $id, array $replacement): void
    {
        $accounts = $this->read();
        foreach ($accounts as $index => $account) {
            if (($account['id'] ?? '') === $id) {
                $accounts[$index] = $replacement;
                $this->write($accounts);
                return;
            }
        }
    }
}
