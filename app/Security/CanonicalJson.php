<?php
declare(strict_types=1);

namespace SecurePackage\Security;

/**
 * Deterministic JSON encoder for integrity records and test vectors.
 */
final class CanonicalJson
{
    public static function encode(mixed $value): string
    {
        if (is_array($value)) {
            if (array_is_list($value)) {
                $items = [];
                foreach ($value as $item) {
                    $items[] = self::encode($item);
                }
                return '[' . implode(',', $items) . ']';
            }
            $keys = array_keys($value);
            usort($keys, static fn($a, $b) => strcmp((string)$a, (string)$b));
            $items = [];
            foreach ($keys as $key) {
                $items[] = json_encode((string)$key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . ':' . self::encode($value[$key]);
            }
            return '{' . implode(',', $items) . '}';
        }
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}
