<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Project\PackageCatalog;

$root = sys_get_temp_dir() . '/secure-package-v5-catalog-' . bin2hex(random_bytes(5));
$c = new PackageCatalog($root);
$id = bin2hex(random_bytes(24));
$c->create($id, 'account:owner-a', 'demo');
$c->assertOwner($id, 'account:owner-a');
try { $c->assertOwner($id, 'account:owner-b'); throw new RuntimeException('Unauthorized owner was accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Package does not exist.') throw $e; }
$c->revoke($id, 'account:owner-a');
try { $c->assertAvailable($id); throw new RuntimeException('Revoked package was accepted as available.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Package is revoked.') throw $e; }

echo "Package authorization tests passed.\n";
