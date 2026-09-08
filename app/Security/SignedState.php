<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/**
 * Provides HMAC-authenticated state blobs for server-held lifecycle records.
 */
final class SignedState
{
    public function __construct(private readonly string $secret)
    {
        if (strlen($secret) < 32) {
            throw new RuntimeException('State signing secret is too short.');
        }
    }

    public function seal(array $payload): string
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $body = base64_encode($json);
        $mac = hash_hmac('sha256', $body, $this->secret, true);
        return $body . '.' . rtrim(strtr(base64_encode($mac), '+/', '-_'), '=');
    }

    public function open(string $token): array
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            throw new RuntimeException('Invalid signed state.');
        }
        $body = (string) $parts[0];
        $encodedMac = strtr((string) $parts[1], '-_', '+/');
        $encodedMac .= str_repeat('=', (4 - strlen($encodedMac) % 4) % 4);
        $mac = base64_decode($encodedMac, true);
        if ($mac === false || strlen($mac) !== 32) {
            throw new RuntimeException('Invalid signed state.');
        }
        $expected = hash_hmac('sha256', $body, $this->secret, true);
        if (!hash_equals($expected, $mac)) {
            throw new RuntimeException('Invalid signed state.');
        }
        $json = base64_decode($body, true);
        if ($json === false) {
            throw new RuntimeException('Invalid signed state.');
        }
        $payload = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($payload)) {
            throw new RuntimeException('Invalid signed state.');
        }
        return $payload;
    }
}
