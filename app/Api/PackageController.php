<?php
declare(strict_types=1);

namespace SecurePackage\Api;

use RuntimeException;
use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Project\V14PackageService;
use SecurePackage\Security\AccessContext;
use SecurePackage\Security\ApplicationSecrets;
use SecurePackage\Security\AccountStore;
use SecurePackage\Security\AuthorizationService;
use SecurePackage\Security\SecurityPolicy;
use SecurePackage\Security\FileProjectNameRegistry;
use SecurePackage\Security\PackageAccessTokenStore;
use SecurePackage\Security\RateLimiter;
use SecurePackage\Security\RestoreTokenStore;
use SecurePackage\Security\Validator;
use SecurePackage\Security\WebSecurity;
use SecurePackage\Storage\AuditLogger;
use SecurePackage\Storage\FileStore;
use SecurePackage\Storage\JobStore;
use SecurePackage\Storage\ResumableUploadStore;

final class PackageController
{
    public function __construct(
        private readonly array $config,
        private readonly JobStore $jobs,
        private readonly RateLimiter $rateLimiter,
        private readonly ArchiveWorkflow $archives,
        private readonly ResumableUploadStore $uploads,
        private readonly PackageCatalog $catalog,
        private readonly PackageAccessTokenStore $accessTokens,
        private readonly AccountStore $accounts,
        private readonly AuditLogger $audit,
        private readonly AuthorizationService $authorization
    ) {}

    public function me(): never
    {
        JsonResponse::send([
            'ok' => true,
            'authenticated' => AccessContext::isAuthenticated(),
            'account_id' => AccessContext::accountId(),
        ]);
    }

    public function register(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $username = (string) ($input['username'] ?? '');
        $password = (string) ($input['password'] ?? '');
        try {
            $id = $this->accounts->register($username, $password);
            WebSecurity::login($id);
            $this->audit->event('account.registered', ['account_id' => $id]);
            sodium_memzero($password);
            JsonResponse::send(['ok' => true, 'authenticated' => true, 'account_id' => $id, 'csrf' => WebSecurity::csrfToken()], 201);
        } catch (\Throwable) {
            sodium_memzero($password);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to create account.'], 422);
        }
    }

    public function login(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $username = (string) ($input['username'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $userKey = 'login:user:' . hash('sha256', strtolower(trim($username)) . '|' . $ip);
        $ipKey = 'login:ip:' . hash('sha256', $ip);
        if (!$this->rateLimiter->allow($ipKey) || !$this->rateLimiter->allow($userKey)) {
            sodium_memzero($password);
            JsonResponse::send(['ok' => false, 'error' => 'Too many login attempts.'], 429);
        }
        $id = $this->accounts->verify($username, $password);
        sodium_memzero($password);
        if ($id === null) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to sign in.'], 401);
        }
        $this->rateLimiter->success($userKey);
        $this->rateLimiter->success($ipKey);
        WebSecurity::login($id);
        $this->audit->event('account.logged_in', ['account_id' => $id]);
        JsonResponse::send(['ok' => true, 'authenticated' => true, 'account_id' => $id, 'csrf' => WebSecurity::csrfToken()]);
    }

    public function logout(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $id = AccessContext::accountId();
        WebSecurity::logout();
        $this->audit->event('account.logged_out', ['account_id' => $id]);
        JsonResponse::send(['ok' => true, 'authenticated' => false, 'csrf' => WebSecurity::csrfToken()]);
    }

    public function uploadInit(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $total = (int) ($input['total_bytes'] ?? 0);
        $sha256 = isset($input['sha256']) ? strtolower((string) $input['sha256']) : null;
        try {
            $result = $this->uploads->initialize($total, AccessContext::ownerId(), $sha256);
            JsonResponse::send(['ok' => true, 'upload' => $result], 201);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to initialize upload.'], 422);
        }
    }

    public function uploadChunk(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $id = (string) ($_SERVER['HTTP_X_UPLOAD_ID'] ?? '');
        $offset = (int) ($_SERVER['HTTP_X_UPLOAD_OFFSET'] ?? -1);
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
        if ($contentLength < 1 || $contentLength > (int) $this->config['limits']['upload_chunk_bytes']) {
            JsonResponse::send(['ok' => false, 'error' => 'Upload chunk is too large.'], 413);
        }
        $chunk = file_get_contents('php://input');
        if ($chunk === false || strlen($chunk) > (int) $this->config['limits']['upload_chunk_bytes']) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to read upload chunk.'], 400);
        }
        try {
            $state = $this->uploads->append($id, $offset, $chunk, AccessContext::ownerId());
            JsonResponse::send(['ok' => true, 'upload' => $state]);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Upload chunk rejected.'], 409);
        }
    }

    public function uploadComplete(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $uploadId = (string) ($input['upload_id'] ?? '');
        try {
            $zip = $this->uploads->finalize($uploadId, AccessContext::ownerId());
            try {
                $job = $this->archives->initialize($zip);
                $state = $this->jobs->readState($job['job_id']);
                $this->jobs->writeState($job['job_id'], array_merge($state, ['owner_hash' => hash('sha256', AccessContext::ownerId())]));
                $public = $this->archives->publicState($this->jobs->readState($job['job_id']));
                $this->audit->event('upload.completed', ['job_id' => $job['job_id'], 'account_id' => AccessContext::accountId()]);
                JsonResponse::send(['ok' => true, 'job_id' => $job['job_id'], 'state' => $public]);
            } finally {
                $this->uploads->remove($uploadId);
            }
        } catch (\Throwable) {
            $this->uploads->remove($uploadId);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to finalize upload.'], 422);
        }
    }

    public function archiveStep(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $jobId = (string) ($input['job_id'] ?? '');
        $archiveId = (string) ($input['archive_id'] ?? '');
        $password = (string) ($input['password'] ?? '');
        try {
            $this->jobs->assertOwner($jobId, AccessContext::ownerId());
            $rateKey = 'archive:' . $jobId . ':' . $archiveId . ':' . hash('sha256', AccessContext::ownerId());
            if (!$this->rateLimiter->allow($rateKey)) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Too many archive password attempts.'], 429);
            }
            try {
                $state = $this->archives->process($jobId, $archiveId, $password);
                $this->rateLimiter->success($rateKey);
                sodium_memzero($password);
                JsonResponse::send(['ok' => true, 'state' => $state]);
            } catch (\Throwable) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Unable to open archive with the supplied password.'], 422);
            }
        } catch (\Throwable) {
            sodium_memzero($password);
            JsonResponse::send(['ok' => false, 'error' => 'Archive job was not found.'], 404);
        }
    }

    public function build(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $jobId = (string) ($input['job_id'] ?? '');
        $name = (string) ($input['project_name'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $pattern = (string) ($input['pattern'] ?? '');
        $createRecovery = (bool) ($input['create_recovery'] ?? true);
        try {
            $this->jobs->assertOwner($jobId, AccessContext::ownerId());
            $state = $this->jobs->readState($jobId);
            if (($state['status'] ?? '') !== 'ready_to_build') JsonResponse::send(['ok' => false, 'error' => 'Archive extraction is not complete.'], 409);
            Validator::validateProjectName($name); Validator::validatePassword($password); Validator::validatePattern($pattern);
            $service = $this->makePackageService();
            $result = $service->build($this->archives->sourceDirectory($jobId), $name, $password, $pattern, $createRecovery);
            $portable = $result['package_dir'] . '.spkg14';
            try {
                (new PackageArchive())->create($result['package_dir'], $portable);
            } catch (\Throwable $archiveError) {
                $this->removePath($portable);
                $this->removePath($result['package_dir']);
                throw $archiveError;
            }
            $this->catalog->create($result['package_id'], AccessContext::ownerId(), $name);
            $token = $this->accessTokens->issue($result['package_id'], AccessContext::ownerId(), false);
            $this->audit->event('package.created', ['package_id' => $result['package_id'], 'account_id' => AccessContext::accountId(), 'nodes' => $result['stats']['nodes'] ?? null, 'format' => 'SECURE-PKG-V14']);
            sodium_memzero($password); sodium_memzero($pattern);
            JsonResponse::send([
                'ok' => true,
                'package_id' => $result['package_id'],
                'download_token' => $token,
                'download' => 'download.php?token=' . rawurlencode($token),
                'stats' => $result['stats'] ?? $result,
                'recovery_key' => $result['recovery_key'] ?? null,
                'format' => 'SECURE-PKG-V14',
            ], 201);
        } catch (\Throwable) {
            sodium_memzero($password); sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to build package.'], 422);
        }
    }

    public function decrypt(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $packageId = (string) ($input['package_id'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $pattern = (string) ($input['pattern'] ?? '');
        $recoveryKey = isset($input['recovery_key']) ? trim((string) $input['recovery_key']) : null;
        $rateKey = 'package:' . $packageId . ':' . hash('sha256', AccessContext::ownerId());
        if (!$this->rateLimiter->allow($rateKey)) {
            sodium_memzero($password); sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => 'Too many failed attempts.'], 429);
        }
        try {
            if ($recoveryKey === null || $recoveryKey === '') {
                Validator::validatePassword($password);
                Validator::validatePattern($pattern);
            }
            $record = $this->catalog->get($packageId);
            if (($record['revoked_at'] ?? null) !== null || ($record['expires_at'] ?? null) !== null && (int) $record['expires_at'] < time()) throw new RuntimeException('Unavailable.');
            $packageDir = $this->config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId;
            $outputDir = $this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-' . bin2hex(random_bytes(16));
            $result = (new V14PackageReader())->restore($packageDir, $outputDir, $password, $pattern, $recoveryKey);
            $tokenStore = new RestoreTokenStore($this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-tokens', (int) $this->config['limits']['restore_ttl_seconds']);
            $restoreToken = $tokenStore->issue($outputDir);
            $this->rateLimiter->success($rateKey);
            $this->audit->event('package.restored', ['package_id' => $packageId, 'account_id' => AccessContext::accountId(), 'files' => $result['files'] ?? null]);
            sodium_memzero($password); sodium_memzero($pattern);
            if (is_string($recoveryKey)) sodium_memzero($recoveryKey);
            JsonResponse::send(['ok' => true, 'restore_download' => 'download-restored.php?token=' . rawurlencode($restoreToken), 'stats' => $result]);
        } catch (\Throwable) {
            sodium_memzero($password); sodium_memzero($pattern);
            if (is_string($recoveryKey)) sodium_memzero($recoveryKey);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to open package.'], 422);
        }
    }

    public function listPackages(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $this->authorization->requireAuthenticated();
        $items = $this->catalog->listForOwner(AccessContext::ownerId());
        JsonResponse::send(['ok' => true, 'packages' => array_map(static function (array $item): array {
            return [
                'package_id' => $item['package_id'],
                'created_at' => $item['created_at'],
                'revoked' => $item['revoked_at'] !== null,
                'expires_at' => $item['expires_at'],
                'format' => 'SECURE-PKG-V14',
            ];
        }, $items)]);
    }

    public function accessToken(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $packageId = (string) ($input['package_id'] ?? '');
        try {
            $this->authorization->requireAuthenticated();
            $record = $this->catalog->assertOwner($packageId, AccessContext::ownerId());
            if (($record['revoked_at'] ?? null) !== null) throw new RuntimeException('Package revoked.');
            $token = $this->accessTokens->issue($packageId, AccessContext::ownerId(), false);
            JsonResponse::send(['ok' => true, 'download' => 'download.php?token=' . rawurlencode($token)]);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Package not available.'], 404);
        }
    }

    public function setExpiry(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json(); $packageId = (string) ($input['package_id'] ?? ''); $expiresIn = (int) ($input['expires_in'] ?? 0);
        try {
            $this->authorization->requireAuthenticated();
            $expiresAt = $expiresIn === 0 ? null : time() + max(300, min($expiresIn, 31536000));
            $this->catalog->setExpiry($packageId, AccessContext::ownerId(), $expiresAt);
            $this->audit->event('package.expiry_changed', ['package_id' => $packageId, 'account_id' => AccessContext::accountId()]);
            JsonResponse::send(['ok' => true]);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to update package expiration.'], 404);
        }
    }

    public function revoke(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json(); $packageId = (string) ($input['package_id'] ?? '');
        try {
            $this->authorization->requireAuthenticated();
            $this->catalog->revoke($packageId, AccessContext::ownerId());
            $this->accessTokens->revokeForPackage($packageId);
            $this->audit->event('package.revoked', ['package_id' => $packageId, 'account_id' => AccessContext::accountId()]);
            JsonResponse::send(['ok' => true]);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to revoke package.'], 404);
        }
    }

    public function delete(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $packageId = (string) ($input['package_id'] ?? '');
        try {
            $this->authorization->requireAuthenticated();
            $record = $this->catalog->assertOwner($packageId, AccessContext::ownerId());
            $path = $this->config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId;
            $portable = $path . '.spkg14';
            $this->removePath($portable);
            $this->removePath($path);
            $this->accessTokens->revokeForPackage($packageId);
            $this->catalog->delete($packageId, AccessContext::ownerId());
            $this->audit->event('package.deleted', ['package_id' => $packageId, 'account_id' => AccessContext::accountId()]);
            JsonResponse::send(['ok' => true]);
        } catch (\Throwable) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to delete package.'], 404);
        }
    }

    public function securityStatus(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        JsonResponse::send([
            'ok' => true,
            'version' => $this->config['app']['version'],
            'format' => $this->config['app']['format'],
            'browser_format' => 'SECURE-BROWSER-V13',
            'server_package_format' => 'SECURE-PKG-V14',
            'author' => $this->config['app']['author'],
            'crypto' => ['kdf' => 'argon2id13', 'aead' => 'xchacha20poly1305-ietf', 'stream' => 'secretstream-xchacha20poly1305', 'key_wrap' => 'xchacha20poly1305-ietf', 'key_separation' => 'HKDF-SHA-256'],
            'controls' => ['csrf' => true, 'same_origin' => true, 'rate_limiting' => true, 'resumable_uploads' => true, 'tamper_evident_audit' => true, 'package_ownership' => true, 'header_binding' => true, 'external_key_wrap' => true, 'no_overwrite_restore' => true]
        ]);
    }

    private function removePath(string $path): void
    {
        if (is_file($path) || is_link($path)) { @unlink($path); return; }
        if (!is_dir($path)) return;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) {
            $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($path);
    }

    private function makePackageService(): V14PackageService
    {
        $pepper = ApplicationSecrets::namePepper($this->config['storage']['root']);
        $registry = new FileProjectNameRegistry($this->config['storage']['root'] . DIRECTORY_SEPARATOR . 'reserved-names.db', $pepper);
        return new V14PackageService(new \SecurePackage\Project\V14PackageBuilder(), new FileStore($this->config['storage']['packages']), $registry);
    }
}
