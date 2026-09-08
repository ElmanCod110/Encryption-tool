<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Security\SecurityDiagnostics;
use SecurePackage\Security\WebSecurity;
WebSecurity::applyHeaders(true);
header('Content-Type: application/json; charset=utf-8');
$data=SecurityDiagnostics::run(dirname(__DIR__));
http_response_code($data['secure'] ? 200 : 503);
echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
