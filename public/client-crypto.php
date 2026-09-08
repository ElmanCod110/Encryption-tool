<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\JsonResponse;
use SecurePackage\Client\BrowserEnvelope;
use SecurePackage\Security\WebSecurity;

$config = require dirname(__DIR__) . '/config/config.php';
WebSecurity::startSession();
WebSecurity::applyHeaders();

WebSecurity::assertSameOrigin();

try {
    $packageId = (string) ($_GET['package_id'] ?? '');
    JsonResponse::send(['ok' => true, 'envelope' => BrowserEnvelope::descriptor($packageId)]);
} catch (Throwable) {
    JsonResponse::send(['ok' => false, 'error' => 'Unable to prepare client cryptography.'], 400);
}
