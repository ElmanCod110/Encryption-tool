<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\UnifiedBrowserPackage;
use SecurePackage\Security\WebSecurity;
WebSecurity::startSession();
WebSecurity::applyHeaders(true);
header('Cache-Control: no-store, max-age=0');
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok'=>true,'descriptor'=>UnifiedBrowserPackage::descriptor()],JSON_THROW_ON_ERROR);
