<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\SignedState;

$state = new SignedState(random_bytes(32));
$token = $state->seal(['purpose' => 'test', 'created_at' => time()]);
$opened = $state->open($token);
if (($opened['purpose'] ?? null) !== 'test') throw new RuntimeException('Signed state round-trip failed.');
$parts = explode('.', $token, 2);
$parts[0] .= 'x';
try {
    $state->open(implode('.', $parts));
    throw new RuntimeException('Tampered signed state was accepted.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Invalid signed state.') throw $e;
}
echo "Signed state tests passed.\n";
