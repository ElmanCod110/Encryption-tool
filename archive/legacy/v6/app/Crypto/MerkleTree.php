<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

final class MerkleTree
{
    private const DOMAIN_LEAF = 'SecurePackage|V10|MERKLE|LEAF|';
    private const DOMAIN_NODE = 'SecurePackage|V10|MERKLE|NODE|';

    public static function root(array $leaves): string
    {
        if ($leaves === []) {
            return hash('sha256', 'SecurePackage|V10|MERKLE|EMPTY');
        }
        $level = array_map(static fn (string $x): string => hex2bin($x), $leaves);
        while (count($level) > 1) {
            $next = [];
            for ($i = 0, $n = count($level); $i < $n; $i += 2) {
                $left = $level[$i];
                $right = $level[$i + 1] ?? $left;
                $next[] = hash('sha256', self::DOMAIN_NODE . $left . $right, true);
            }
            $level = $next;
        }
        return bin2hex($level[0]);
    }

    public static function proof(array $leaves, int $index): array
    {
        if ($index < 0 || $index >= count($leaves)) {
            throw new RuntimeException('Invalid Merkle index.');
        }
        $level = array_map(static fn (string $x): string => hex2bin($x), $leaves);
        $proof = [];
        $position = $index;
        while (count($level) > 1) {
            $sibling = ($position % 2 === 0) ? $position + 1 : $position - 1;
            $isLeft = ($position % 2) === 1;
            $proof[] = ['hash' => bin2hex($level[$sibling] ?? $level[$position]), 'left' => $isLeft];
            $next = [];
            for ($i = 0, $n = count($level); $i < $n; $i += 2) {
                $next[] = hash('sha256', self::DOMAIN_NODE . $level[$i] . ($level[$i + 1] ?? $level[$i]), true);
            }
            $level = $next;
            $position = intdiv($position, 2);
        }
        return $proof;
    }

    public static function verify(string $leafHex, array $proof, string $expectedRoot): bool
    {
        if (!ctype_xdigit($leafHex) || strlen($leafHex) !== 64 || !ctype_xdigit($expectedRoot) || strlen($expectedRoot) !== 64) {
            return false;
        }
        $current = hex2bin($leafHex);
        foreach ($proof as $step) {
            $sibling = hex2bin((string) ($step['hash'] ?? ''));
            if ($sibling === false || !isset($step['left'])) {
                return false;
            }
            $current = (bool) $step['left']
                ? hash('sha256', self::DOMAIN_NODE . $sibling . $current, true)
                : hash('sha256', self::DOMAIN_NODE . $current . $sibling, true);
        }
        return hash_equals($expectedRoot, bin2hex($current));
    }

    public static function leaf(string $recordId, string $ciphertext): string
    {
        return hash('sha256', self::DOMAIN_LEAF . $recordId . '|' . $ciphertext, false);
    }
}
