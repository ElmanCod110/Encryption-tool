<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Api\JsonResponse;
use SecurePackage\Security\WebSecurity;
WebSecurity::startSession(); WebSecurity::applyHeaders(); header('Cache-Control: no-store');
JsonResponse::send(['ok' => false, 'error' => 'The V13 browser package API was retired. This application accepts the unified SPKG format only.', 'format' => 'SPKG'], 410);
