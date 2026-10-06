<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\V13Descriptor;
use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders(false);
header('Content-Type: application/json; charset=utf-8');
$config = require dirname(__DIR__) . '/config/config.php';
$checks = [
    'php' => PHP_VERSION_ID >= 80200,
    'sodium' => extension_loaded('sodium'),
    'zip' => extension_loaded('zip'),
    'https' => empty($config['security']['require_https']) || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
];
$ok = !in_array(false, $checks, true);
echo json_encode([
    'ok' => $ok,
    'status' => $ok ? 'healthy' : 'degraded',
    'product' => $config['app']['name'],
    'version' => $config['app']['version'],
    'browser_format' => V13Descriptor::FORMAT,
    'checks' => $checks,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
