<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\KeyEnvelope;
use SecurePackage\Crypto\KeyDerivationV10;
use SecurePackage\Security\RecoveryKey;

$salt = random_bytes(KeyDerivationV10::SALT_BYTES);
$root = random_bytes(32);
$password = 'Strong!Password2026';
$pattern = 'gG7!xY2_Ab9#Qp';
$slot = KeyEnvelope::create($root, $password, $pattern, $salt);
$recovered = KeyEnvelope::unwrapCredentialSlot($slot, $password, $pattern, $salt);
if (!hash_equals($root, $recovered)) throw new RuntimeException('Credential unwrap failed.');
$newSlot = KeyEnvelope::rotateCredentialSlot($slot, $password, $pattern, 'New!Password2026X', 'zZ8@pattern#42Q', $salt);
$rotated = KeyEnvelope::unwrapCredentialSlot($newSlot, 'New!Password2026X', 'zZ8@pattern#42Q', $salt);
if (!hash_equals($root, $rotated)) throw new RuntimeException('Credential rotation failed.');
$recovery = RecoveryKey::generate();
$recoverySlot = KeyEnvelope::createRecoverySlot($root, $recovery, $salt);
if (strlen($recovery) !== 64) throw new RuntimeException('Invalid recovery key length.');
RecoveryKey::validate($recovery);
echo "V10 key envelope tests passed.\n";
