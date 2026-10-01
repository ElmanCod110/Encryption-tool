<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Project\V14Descriptor;

$kdf = V14Descriptor::kdfProfile();
if ($kdf['name'] !== 'argon2id13' || $kdf['salt_bytes'] !== 32 || $kdf['key_bytes'] !== 32) throw new RuntimeException('V14 descriptor KDF failed.');
if (V14Descriptor::FORMAT !== 'SECURE-PKG-V14' || V14Descriptor::VERSION !== 14) throw new RuntimeException('V14 descriptor identity failed.');
echo "V14 descriptor tests passed.\n";
