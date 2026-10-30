<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders(true);
http_response_code(410);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode([
    'ok' => false,
    'error' => 'The legacy V13 browser endpoint has been retired. This application supports SPKG only.',
    'format' => 'SPKG',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
