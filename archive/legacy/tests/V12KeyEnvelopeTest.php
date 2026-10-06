<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\KeyEnvelope;
if (!extension_loaded('sodium')) { echo "V12 key envelope test skipped.\n"; exit(0); }
$root=random_bytes(32);$salt=random_bytes(32);$p1='Aa9!PrimaryPassword2026';$t1='Pattern#A9_xYp!';$p2='Bb8!RotatedPassword2027';$t2='Pattern#B8_zYq!';
$slot=KeyEnvelope::create($root,$p1,$t1,$salt);$recovered=KeyEnvelope::unwrapCredentialSlot($slot,$p1,$t1,$salt);if(!hash_equals($root,$recovered))throw new RuntimeException('Primary key envelope failed.');
$rotated=KeyEnvelope::rotateCredentialSlot($slot,$p1,$t1,$p2,$t2,$salt);$recovered2=KeyEnvelope::unwrapCredentialSlot($rotated,$p2,$t2,$salt);if(!hash_equals($root,$recovered2))throw new RuntimeException('Credential rotation failed.');
try{KeyEnvelope::unwrapCredentialSlot($rotated,$p1,$t1,$salt);throw new RuntimeException('Old credentials remained valid.');}catch(RuntimeException $e){if($e->getMessage()==='Old credentials remained valid.')throw $e;}
sodium_memzero($root);sodium_memzero($recovered);sodium_memzero($recovered2);echo "V12 key envelope tests passed.\n";
