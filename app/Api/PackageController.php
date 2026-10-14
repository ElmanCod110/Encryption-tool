<?php
declare(strict_types=1);

namespace SecurePackage\Api;

use InvalidArgumentException;
use RuntimeException;
use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Archive\ArchiveProcessingException;
use SecurePackage\Archive\ArchiveStepConflictException;
use SecurePackage\Project\PackageArchive;
use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageNotAvailableException;
use SecurePackage\Project\PackageRestoreRejectedException;
use SecurePackage\Project\PackageStorageException;
use SecurePackage\Project\V14PackageReader;
use SecurePackage\Project\V14PackageService;
use SecurePackage\Security\AccessContext;
use SecurePackage\Security\ApplicationSecrets;
use SecurePackage\Security\AccountStore;
use SecurePackage\Security\AuthenticationRequiredException;
use SecurePackage\Security\DuplicateAccountException;
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
use SecurePackage\Storage\JobNotAvailableException;
use SecurePackage\Storage\ResumableUploadStore;
use SecurePackage\Storage\QuotaExceededException;
use SecurePackage\Storage\UploadException;

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
        } catch (DuplicateAccountException) {
            sodium_memzero($password);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to create account.'], 409);
        } catch (InvalidArgumentException) {
            sodium_memzero($password);
            JsonResponse::send(['ok' => false, 'error' => 'Invalid account details.'], 422);
        } catch (\Throwable $exception) {
            sodium_memzero($password);
            throw $exception;
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
        try {
            if (!$this->rateLimiter->allow($ipKey) || !$this->rateLimiter->allow($userKey)) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Too many login attempts.'], 429);
            }
            $id = $this->accounts->verify($username, $password);
        } catch (\Throwable $exception) {
            sodium_memzero($password);
            throw $exception;
        }
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
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $ipRateKey = 'upload-init:ip:' . hash('sha256', $ip);
        if (!$this->rateLimiter->allow($ipRateKey)) {
            JsonResponse::send(['ok' => false, 'error' => 'Too many upload initialization attempts.'], 429);
        }
        try {
            // Purge expired upload reservations before enforcing per-owner quotas.
            $this->uploads->cleanup();
            $result = $this->uploads->initialize($total, AccessContext::ownerId(), $sha256);
            JsonResponse::send(['ok' => true, 'upload' => $result], 201);
        } catch (QuotaExceededException) {
            JsonResponse::send(['ok' => false, 'error' => 'Active upload quota exceeded.'], 429);
        } catch (UploadException $exception) {
            JsonResponse::send(['ok' => false, 'error' => $exception->publicMessage], $exception->statusCode);
        } catch (\Throwable $exception) {
            throw $exception;
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
        } catch (UploadException $exception) {
            JsonResponse::send(['ok' => false, 'error' => $exception->publicMessage], $exception->statusCode);
        } catch (\Throwable $exception) {
            throw $exception;
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
        } catch (UploadException $exception) {
            $this->uploads->remove($uploadId);
            JsonResponse::send(['ok' => false, 'error' => $exception->publicMessage], $exception->statusCode);
        } catch (\Throwable $exception) {
            $this->uploads->remove($uploadId);
            throw $exception;
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
            $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            $ipRateKey = 'archive:ip:' . hash('sha256', $ip);
            if (!$this->rateLimiter->allow($ipRateKey) || !$this->rateLimiter->allow($rateKey)) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Too many archive password attempts.'], 429);
            }
            try {
                $state = $this->archives->process($jobId, $archiveId, $password);
                $this->rateLimiter->success($rateKey);
                $this->rateLimiter->success($ipRateKey);
                sodium_memzero($password);
                JsonResponse::send(['ok' => true, 'state' => $state]);
            } catch (JobNotAvailableException) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Archive job was not found.'], 404);
            } catch (ArchiveStepConflictException) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Archive step is no longer available.'], 409);
            } catch (ArchiveProcessingException) {
                sodium_memzero($password);
                JsonResponse::send(['ok' => false, 'error' => 'Unable to open archive with the supplied password.'], 422);
            } catch (\Throwable $exception) {
                sodium_memzero($password);
                throw $exception;
            }
        } catch (JobNotAvailableException) {
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
        $packageCreated = false;
        $packageDirectory = null;
        $portableArchive = null;
        try {
            $this->jobs->assertOwner($jobId, AccessContext::ownerId());
            $state = $this->jobs->readState($jobId);
            if (($state['status'] ?? '') !== 'ready_to_build') JsonResponse::send(['ok' => false, 'error' => 'Archive extraction is not complete.'], 409);
            Validator::validateProjectName($name); Validator::validatePassword($password); Validator::validatePattern($pattern);
            $service = $this->makePackageService();
            $result = $service->build($this->archives->sourceDirectory($jobId), $name, $password, $pattern, $createRecovery);
            $packageDirectory = $result['package_dir'];
            $portableArchive = $packageDirectory . '.spkg14';
            try {
                (new PackageArchive())->create($packageDirectory, $portableArchive);
            } catch (\Throwable $archiveError) {
                $this->removePath($portableArchive);
                $this->removePath($packageDirectory);
                throw $archiveError;
            }
            // The portable archive is the canonical stored package. Keeping both the extracted
            // package directory and .spkg14 duplicates encrypted bytes and wastes disk space.
            $this->removePath($result['package_dir']);
            $this->catalog->create($result['package_id'], AccessContext::ownerId(), $name);
            $packageCreated = true;
            $token = $this->accessTokens->issue($result['package_id'], AccessContext::ownerId(), false);
            $this->audit->event('package.created', ['package_id' => $result['package_id'], 'account_id' => AccessContext::accountId(), 'nodes' => $result['stats']['nodes'] ?? null, 'format' => 'SECURE-PKG-V14']);
            // The encrypted package is now stored and catalogued; remove the plaintext extraction job.
            $this->removeJobDirectory($jobId);
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
        } catch (JobNotAvailableException $exception) {
            $this->cleanupFailedBuild($portableArchive, $packageDirectory, $packageCreated);
            sodium_memzero($password); sodium_memzero($pattern);
            if ($packageCreated) {
                throw $exception;
            }
            JsonResponse::send(['ok' => false, 'error' => 'Archive job was not found.'], 404);
        } catch (InvalidArgumentException) {
            $this->cleanupFailedBuild($portableArchive, $packageDirectory, $packageCreated);
            sodium_memzero($password); sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to build package.'], 422);
        } catch (\Throwable $exception) {
            // Preserve the plaintext source and clean only incomplete encrypted artifacts.
            // Unexpected storage, ZIP, catalog, and programming failures must reach the API
            // boundary as HTTP 500 instead of being mislabeled as client input errors.
            $this->cleanupFailedBuild($portableArchive, $packageDirectory, $packageCreated);
            sodium_memzero($password); sodium_memzero($pattern);
            throw $exception;
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
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $ipRateKey = 'package:ip:' . hash('sha256', $ip);
        if (!$this->rateLimiter->allow($ipRateKey) || !$this->rateLimiter->allow($rateKey)) {
            sodium_memzero($password); sodium_memzero($pattern);
            if (is_string($recoveryKey)) sodium_memzero($recoveryKey);
            JsonResponse::send(['ok' => false, 'error' => 'Too many failed attempts.'], 429);
        }
        $outputDir = null;
        try {
            if ($recoveryKey === null || $recoveryKey === '') {
                Validator::validatePassword($password);
                Validator::validatePattern($pattern);
            }
            // Centralize revocation and expiry checks so decrypt uses the same boundary as downloads.
            $this->catalog->assertAvailable($packageId);
            $packageDir = $this->config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId;
            $temporaryPackageDir = null;
            $portable = $packageDir . '.spkg14';
            try {
                if (!is_dir($packageDir)) {
                    if (!is_file($portable)) throw new RuntimeException('Package does not exist.');
                    $temporaryPackageDir = $this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'package-' . bin2hex(random_bytes(16));
                    (new PackageArchive())->extract($portable, $temporaryPackageDir);
                    $packageDir = $temporaryPackageDir;
                }
                $outputDir = $this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-' . bin2hex(random_bytes(16));
                $result = (new V14PackageReader())->restore($packageDir, $outputDir, $password, $pattern, $recoveryKey);
            } finally {
                if ($temporaryPackageDir !== null) {
                    $this->removePath($temporaryPackageDir);
                    if (file_exists($temporaryPackageDir) || is_link($temporaryPackageDir)) {
                        throw new PackageStorageException('Unable to clean temporary package extraction.');
                    }
                }
            }
            $tokenStore = new RestoreTokenStore($this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-tokens', (int) $this->config['limits']['restore_ttl_seconds']);
            $restoreToken = $tokenStore->issue($outputDir);
            $this->rateLimiter->success($rateKey);
            $this->rateLimiter->success($ipRateKey);
            $this->audit->event('package.restored', ['package_id' => $packageId, 'account_id' => AccessContext::accountId(), 'files' => $result['files'] ?? null]);
            sodium_memzero($password); sodium_memzero($pattern);
            if (is_string($recoveryKey)) sodium_memzero($recoveryKey);
            JsonResponse::send(['ok' => true, 'restore_download' => 'download-restored.php?token=' . rawurlencode($restoreToken), 'stats' => $result]);
        } catch (PackageNotAvailableException) {
            $this->cleanupFailedRestore($outputDir, $password, $pattern, $recoveryKey);
            JsonResponse::send(['ok' => false, 'error' => 'Package not available.'], 404);
        } catch (PackageRestoreRejectedException|InvalidArgumentException) {
            $this->cleanupFailedRestore($outputDir, $password, $pattern, $recoveryKey);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to open package.'], 422);
        } catch (PackageStorageException $exception) {
            $this->cleanupFailedRestore($outputDir, $password, $pattern, $recoveryKey);
            throw $exception;
        } catch (\Throwable $exception) {
            $this->cleanupFailedRestore($outputDir, $password, $pattern, $recoveryKey);
            throw $exception;
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
        } catch (AuthenticationRequiredException $exception) {
            throw $exception;
        } catch (PackageNotAvailableException) {
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
        } catch (AuthenticationRequiredException $exception) {
            throw $exception;
        } catch (PackageNotAvailableException) {
            JsonResponse::send(['ok' => false, 'error' => 'Package not available.'], 404);
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
        } catch (AuthenticationRequiredException $exception) {
            throw $exception;
        } catch (PackageNotAvailableException) {
            JsonResponse::send(['ok' => false, 'error' => 'Package not available.'], 404);
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
        } catch (AuthenticationRequiredException $exception) {
            throw $exception;
        } catch (PackageNotAvailableException) {
            JsonResponse::send(['ok' => false, 'error' => 'Package not available.'], 404);
        }
    }

    public function securityStatus(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        JsonResponse::send([
            'ok' => true,
            'version' => $this->config['app']['version'],
            'version_string' => $this->config['app']['version_string'],
            'format' => $this->config['app']['format'],
            'browser_format' => 'SECURE-BROWSER-V13',
            'server_package_format' => 'SECURE-PKG-V14',
            'author' => $this->config['app']['author'],
            'crypto' => ['kdf' => 'argon2id13', 'aead' => 'xchacha20poly1305-ietf', 'stream' => 'secretstream-xchacha20poly1305', 'key_wrap' => 'xchacha20poly1305-ietf', 'key_separation' => 'HKDF-SHA-256'],
            'controls' => ['csrf' => true, 'same_origin' => true, 'rate_limiting' => true, 'resumable_uploads' => true, 'tamper_evident_audit' => true, 'package_ownership' => true, 'header_binding' => true, 'external_key_wrap' => true, 'no_overwrite_restore' => true]
        ]);
    }

    private function cleanupFailedRestore(?string $outputDir, string &$password, string &$pattern, ?string &$recoveryKey): void
    {
        try {
            if (is_string($outputDir)) {
                $this->removePath($outputDir);
                if (file_exists($outputDir) || is_link($outputDir)) {
                    throw new PackageStorageException('Unable to clean incomplete restore output.');
                }
            }
        } finally {
            sodium_memzero($password);
            sodium_memzero($pattern);
            if (is_string($recoveryKey)) sodium_memzero($recoveryKey);
        }
    }

    private function cleanupFailedBuild(?string $portableArchive, ?string $packageDirectory, bool $packageCreated): void
    {
        if ($packageCreated) {
            return;
        }

        foreach ([$portableArchive, $packageDirectory] as $path) {
            if (!is_string($path)) {
                continue;
            }

            $this->removePath($path);
            if (file_exists($path) || is_link($path)) {
                throw new RuntimeException('Unable to clean incomplete package artifacts.');
            }
        }
    }

    private function removeJobDirectory(string $jobId): void
    {
        $path = $this->jobs->path($jobId);
        $this->removePath($path);
        if (file_exists($path) || is_link($path)) {
            throw new RuntimeException('Unable to remove plaintext job data.');
        }
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
