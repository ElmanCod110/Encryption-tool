<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\BrowserEnvelope;

$id = bin2hex(random_bytes(24));
$descriptor = BrowserEnvelope::descriptor($id);
if (($descriptor['format'] ?? null) !== BrowserEnvelope::FORMAT || ($descriptor['content_encryption'] ?? null) !== 'AES-256-GCM') {
    throw new RuntimeException('Browser envelope descriptor test failed.');
}
echo "Client envelope tests passed.\n";
