<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

final class V14Merkle
{
    private const LEAF_DOMAIN = 'SecurePackage|V14|MERKLE|LEAF|';
    private const NODE_DOMAIN = 'SecurePackage|V14|MERKLE|NODE|';
    private const EMPTY_DOMAIN = 'SecurePackage|V14|MERKLE|EMPTY';

    public static function leaf(string $recordId, string $cipherHash, int $plainSize): string
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $recordId) || !preg_match('/^[a-f0-9]{64}$/', $cipherHash) || $plainSize < 0) throw new RuntimeException('Invalid Merkle leaf.');
        return hash('sha256', self::LEAF_DOMAIN . $recordId . '|' . $cipherHash . '|' . $plainSize, false);
    }

    public static function root(array $leaves): string
    {
        if ($leaves === []) return hash('sha256', self::EMPTY_DOMAIN);
        $level = [];
        foreach ($leaves as $leaf) {
            if (!is_string($leaf) || !preg_match('/^[a-f0-9]{64}$/', $leaf)) throw new RuntimeException('Invalid Merkle leaf.');
            $level[] = hex2bin($leaf);
        }
        while (count($level) > 1) {
            $next = [];
            for ($i = 0, $n = count($level); $i < $n; $i += 2) {
                $right = $level[$i + 1] ?? $level[$i];
                $next[] = hash('sha256', self::NODE_DOMAIN . $level[$i] . $right, true);
            }
            $level = $next;
        }
        return bin2hex($level[0]);
    }
}
