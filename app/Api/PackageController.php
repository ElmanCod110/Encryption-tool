<?php
declare(strict_types=1);

namespace TCH\Api;

use RuntimeException;
use TCH\Archive\ArchivePolicy;
use TCH\Archive\ArchiveWorkflow;
use TCH\Crypto\KeyDerivation;
use TCH\Project\PackageReader;
use TCH\Project\PackageArchive;
use TCH\Project\PackageService;
use TCH\Security\ProjectNameRegistry;
use TCH\Security\FileProjectNameRegistry;
use TCH\Security\RateLimiter;
use TCH\Security\Validator;
use TCH\Security\WebSecurity;
use TCH\Storage\FileStore;
use TCH\Storage\JobStore;

final class PackageController
{
    public function __construct(
        private readonly array $config,
        private readonly JobStore $jobs,
        private readonly RateLimiter $rateLimiter,
        private readonly ArchiveWorkflow $archives
    ) {}

    public function upload(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        if (!isset($_FILES['archive']) || !is_array($_FILES['archive'])) {
            JsonResponse::send(['ok' => false, 'error' => 'Archive upload is required.'], 400);
        }
        $file = $_FILES['archive'];
        if ((int) ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            JsonResponse::send(['ok' => false, 'error' => 'Archive upload failed.'], 400);
        }
        $max = (int) $this->config['limits']['max_upload_bytes'];
        if ((int) ($file['size'] ?? 0) <= 0 || (int) $file['size'] > $max) {
            JsonResponse::send(['ok' => false, 'error' => 'Archive exceeds upload limits.'], 400);
        }
        $temp = $this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'upload-' . bin2hex(random_bytes(16)) . '.zip';
        if (!move_uploaded_file((string) $file['tmp_name'], $temp)) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to store uploaded archive.'], 500);
        }
        try {
            $job = $this->archives->initialize($temp);
            $state = $this->jobs->readState($job['job_id']);
            $state['owner_hash'] = hash('sha256', WebSecurity::ownerToken());
            $this->jobs->writeState($job['job_id'], $state);
            JsonResponse::send(['ok' => true, 'job_id' => $job['job_id'], 'state' => $this->archives->publicState($state)], 201);
        } finally {
            @unlink($temp);
        }
    }

    public function archiveStep(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $jobId = (string) ($input['job_id'] ?? '');
        $archiveId = (string) ($input['archive_id'] ?? '');
        $password = (string) ($input['password'] ?? '');
        if ($jobId === '' || $archiveId === '') {
            JsonResponse::send(['ok' => false, 'error' => 'Invalid archive request.'], 400);
        }
        try {
            $this->jobs->assertOwner($jobId, WebSecurity::ownerToken());
            $state = $this->jobs->readState($jobId);
            $rateKey = 'archive:' . $jobId . ':' . $archiveId . ':' . hash('sha256', WebSecurity::ownerToken());
            if (!$this->rateLimiter->check($rateKey)) {
                JsonResponse::send(['ok' => false, 'error' => 'Too many failed archive password attempts.'], 429);
            }
            try {
                $newState = $this->archives->process($jobId, $archiveId, $password);
                $this->rateLimiter->success($rateKey);
                JsonResponse::send(['ok' => true, 'state' => $newState]);
            } catch (\Throwable $e) {
                $this->rateLimiter->failure($rateKey);
                JsonResponse::send(['ok' => false, 'error' => 'Unable to open archive with the supplied password.'], 422);
            }
        } catch (\Throwable) {
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
        try {
            $this->jobs->assertOwner($jobId, WebSecurity::ownerToken());
            $state = $this->jobs->readState($jobId);
            if (($state['status'] ?? '') !== 'ready_to_build') {
                JsonResponse::send(['ok' => false, 'error' => 'Archive extraction is not complete.'], 409);
            }
            Validator::validateProjectName($name);
            Validator::validatePassword($password);
            Validator::validatePattern($pattern);

            $service = $this->makePackageService();
            $result = $service->build($this->archives->sourceDirectory($jobId), $name, $password, $pattern);
            $portableFile = $result['package_dir'] . '.tchpkg';
            (new PackageArchive())->create($result['package_dir'], $portableFile);
            $this->writePackageRecord($result['package_id'], $name, $portableFile);
            sodium_memzero($password);
            sodium_memzero($pattern);
            JsonResponse::send(['ok' => true, 'package_id' => $result['package_id'], 'download' => 'download.php?id=' . rawurlencode($result['package_id']), 'stats' => $result['stats']], 201);
        } catch (\Throwable $e) {
            sodium_memzero($password);
            sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => $e->getMessage()], 422);
        }
    }

    public function decrypt(): never
    {
        WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        $input = Request::json();
        $packageId = (string) ($input['package_id'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $pattern = (string) ($input['pattern'] ?? '');
        if (!preg_match('/^[a-f0-9]{36}$/', $packageId)) {
            JsonResponse::send(['ok' => false, 'error' => 'Unable to open package.'], 404);
        }
        $rateKey = 'package:' . $packageId . ':' . hash('sha256', WebSecurity::ownerToken());
        if (!$this->rateLimiter->check($rateKey)) {
            sodium_memzero($password);
            sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => 'Too many failed attempts.'], 429);
        }
        try {
            Validator::validatePassword($password);
            Validator::validatePattern($pattern);
            $packageDir = $this->config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId;
            $outputDir = $this->config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-' . bin2hex(random_bytes(16));
            $result = (new PackageReader())->restore($packageDir, $outputDir, $password, $pattern);
            $this->rateLimiter->success($rateKey);
            sodium_memzero($password);
            sodium_memzero($pattern);
            JsonResponse::send(['ok' => true, 'restore_token' => basename($outputDir), 'stats' => $result]);
        } catch (\Throwable) {
            $this->rateLimiter->failure($rateKey);
            sodium_memzero($password);
            sodium_memzero($pattern);
            JsonResponse::send(['ok' => false, 'error' => 'Unable to open package.'], 422);
        }
    }


    private function writePackageRecord(string $packageId, string $name, string $portableFile): void
    {
        $root = $this->config['storage']['packages'];
        $record = [
            'package_id' => $packageId,
            'name_hash' => hash('sha256', $name),
            'file' => basename($portableFile),
        ];
        file_put_contents($root . DIRECTORY_SEPARATOR . $packageId . DIRECTORY_SEPARATOR . 'record.json', json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX);
        @chmod($root . DIRECTORY_SEPARATOR . $packageId . DIRECTORY_SEPARATOR . 'record.json', 0600);
    }

    private function makePackageService(): PackageService
    {
        $registry = null;
        $dsn = getenv('TCH_DB_DSN') ?: '';
        if ($dsn !== '') {
            $pdo = new \PDO($dsn, getenv('TCH_DB_USER') ?: null, getenv('TCH_DB_PASS') ?: null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
            $pepper = getenv('TCH_NAME_PEPPER') ?: '';
            if ($pepper === '') {
                throw new RuntimeException('TCH_NAME_PEPPER is required when database name reservations are enabled.');
            }
            $registry = new ProjectNameRegistry($pdo, $pepper);
        }
        if ($registry === null) {
            $pepper = getenv('TCH_NAME_PEPPER') ?: '';
            if ($pepper === '') {
                throw new RuntimeException('TCH_NAME_PEPPER must be configured.');
            }
            $registry = new FileProjectNameRegistry($this->config['storage']['root'] . DIRECTORY_SEPARATOR . 'reserved-names.db', $pepper);
        }
        $store = new FileStore($this->config['storage']['packages']);
        return new PackageService(new \TCH\Project\PackageBuilder(), $store, $registry);
    }
}
