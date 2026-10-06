<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders();
header('Content-Type: application/json; charset=utf-8');

$config = require dirname(__DIR__) . '/config/config.php';
$checks = [
    'php' => version_compare(PHP_VERSION, '8.2.0', '>='),
    'sodium' => extension_loaded('sodium'),
    'zip' => extension_loaded('zip'),
    'pdo_mysql' => extension_loaded('pdo_mysql'),
    'random_bytes' => function_exists('random_bytes'),
    'storage' => is_dir($config['storage']['root']) || @mkdir($config['storage']['root'], 0700, true),
];
$requiredOk = $checks['php'] && $checks['sodium'] && $checks['random_bytes'] && $checks['zip'] && $checks['storage'];
http_response_code($requiredOk ? 200 : 503);
echo json_encode([
    'ok' => $requiredOk,
    'application' => $config['app']['name'],
    'version' => $config['app']['version'],
    'version_string' => $config['app']['version_string'],
    'format' => $config['app']['format'],
    'author' => $config['app']['author'],
    'required' => $checks,
    'optional' => ['pdo_mysql'],
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
