<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\V13Descriptor;
use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders(true);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok' => true, 'descriptor' => V13Descriptor::descriptor()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
