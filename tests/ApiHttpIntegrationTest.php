<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$public = dirname(__DIR__) . '/public';
$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-api-http-' . bin2hex(random_bytes(8));
if (!mkdir($base, 0700, true)) {
    throw new RuntimeException('Unable to create HTTP integration fixture directory.');
}
$log = $base . DIRECTORY_SEPARATOR . 'server.log';

$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($socket === false) {
    throw new RuntimeException('Unable to reserve an HTTP test port.');
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$port = (int) substr(strrchr((string) $address, ':'), 1);
$url = 'http://127.0.0.1:' . $port . '/';
$descriptors = [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']];
$process = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $public], $descriptors, $pipes, dirname(__DIR__));
if (!is_resource($process)) {
    @unlink($log);
    @rmdir($base);
    throw new RuntimeException('Unable to start the PHP HTTP test server.');
}
fclose($pipes[0]);

$request = static function (string $path, string $method = 'GET', array $headers = [], string $body = '') use ($url): array {
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => implode("\r\n", $headers),
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 3,
    ]]);
    $responseBody = @file_get_contents($url . $path, false, $context);
    $responseHeaders = $http_response_header ?? [];
    $status = 0;
    foreach ($responseHeaders as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $match)) {
            $status = (int) $match[1];
            break;
        }
    }
    return ['status' => $status, 'body' => (string) $responseBody, 'headers' => $responseHeaders];
};

$expect = static function (int $status, array $response, string $case): void {
    if ($response['status'] !== $status) {
        throw new RuntimeException($case . ': expected HTTP ' . $status . ', got ' . $response['status'] . '.');
    }
};

try {
    $ready = false;
    for ($attempt = 0; $attempt < 40; $attempt++) {
        $response = $request('api.php?action=unknown-action');
        if ($response['status'] !== 0) {
            $ready = true;
            break;
        }
        usleep(100_000);
    }
    if (!$ready) {
        throw new RuntimeException('PHP HTTP test server did not become ready.');
    }

    $expect(404, $request('api.php?action=unknown-action'), 'Unknown action');
    $expect(405, $request('api.php?action=login', 'GET'), 'GET login method');
    $expect(415, $request('api.php?action=login', 'POST', ['Content-Type: text/plain'], '{}'), 'Login media type');

    $csrfResponse = $request('api.php?action=csrf', 'POST');
    $expect(200, $csrfResponse, 'CSRF bootstrap');
    $payload = json_decode($csrfResponse['body'], true, 16, JSON_THROW_ON_ERROR);
    $csrf = (string) ($payload['csrf'] ?? '');
    if ($csrf === '') throw new RuntimeException('CSRF bootstrap did not return a token.');

    $cookie = '';
    foreach ($csrfResponse['headers'] as $header) {
        if (stripos($header, 'Set-Cookie: SECUREPKGSESSID=') === 0
            && preg_match('/SECUREPKGSESSID=([^;]+)/', $header, $match)) {
            $cookie = 'SECUREPKGSESSID=' . $match[1];
            break;
        }
    }
    if ($cookie === '') throw new RuntimeException('CSRF bootstrap did not set the expected session cookie.');

    $common = ['Content-Type: application/json', 'Cookie: ' . $cookie];
    $expect(403, $request('api.php?action=login', 'POST', $common, '{}'), 'Missing CSRF token');
    $expect(403, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf, 'Origin: https://attacker.example']), '{}'), 'Cross-origin request');
    $expect(400, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{invalid-json'), 'Malformed JSON');

    echo "API HTTP integration tests passed.\n";
} finally {
    proc_terminate($process);
    proc_close($process);
    @unlink($log);
    @rmdir($base);
}
