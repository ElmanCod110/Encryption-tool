<?php
declare(strict_types=1);

namespace SecurePackage\Client;

final class MerkleAccumulator
{
    private array $levels = [];
    private int $count = 0;

    public function push(string $leafHex): void
    {
        $carry = hex2bin($leafHex);
        $level = 0;
        while (isset($this->levels[$level])) {
            $left = $this->levels[$level];
            $carry = hash('sha256', "SecurePackage|V11|NODE|" . $left . $carry, true);
            unset($this->levels[$level]);
            $level++;
        }
        $this->levels[$level] = $carry;
        $this->count++;
    }

    public function root(): string
    {
        if ($this->count === 0) return hash('sha256', 'SecurePackage|V11|EMPTY');
        $carry = null;
        for ($i = 0; $i < count($this->levels); $i++) {
            if (!isset($this->levels[$i])) continue;
            if ($carry === null) $carry = $this->levels[$i];
            else $carry = hash('sha256', "SecurePackage|V11|NODE|" . $this->levels[$i] . $carry, true);
        }
        return bin2hex($carry ?? hash('sha256', 'SecurePackage|V11|EMPTY', true));
    }

    public function count(): int { return $this->count; }
}
