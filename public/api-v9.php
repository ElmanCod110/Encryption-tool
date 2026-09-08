<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\BrowserV9;
use SecurePackage\Security\WebSecurity;
WebSecurity::startSession();
WebSecurity::applyHeaders(true);
$config = require dirname(__DIR__) . '/config/config.php';
$base = $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'client-v9';
@mkdir($base, 0700, true);
function v9_json(array $data, int $status=200): never { http_response_code($status); header('Content-Type: application/json; charset=utf-8'); echo json_encode($data, JSON_UNESCAPED_SLASHES); exit; }
function v9_body(): array { $raw=file_get_contents('php://input'); $data=json_decode($raw?:'{}', true); return is_array($data)?$data:[]; }
function v9_csrf(): void { $provided=(string)($_SERVER['HTTP_X_CSRF_TOKEN']??''); if(!hash_equals(WebSecurity::csrfToken(),$provided)) v9_json(['ok'=>false,'error'=>'Invalid request token.'],403); }
function v9_hex(string $v,int $n): bool { return (bool)preg_match('/^[a-f0-9]{'.$n.'}$/',$v); }
$action=(string)($_GET['action']??'');
if($action==='csrf') v9_json(['ok'=>true,'csrf'=>WebSecurity::csrfToken()]);
v9_csrf();
try {
  if($action==='descriptor') v9_json(['ok'=>true,'descriptor'=>BrowserV9::descriptor()]);
  if($action==='init') {
    $d=v9_body();
    if((int)($d['chunk_size']??0)!==BrowserV9::CHUNK_SIZE) v9_json(['ok'=>false,'error'=>'Unsupported chunk configuration.'],400);
    $resume=(string)($d['resume_id']??'');
    if($resume!=='' && v9_hex($resume,48)) {
      $dir=$base.DIRECTORY_SEPARATOR.hash('sha256',session_id().'|'.$resume);
      if(is_dir($dir) && is_file($dir.'/owner') && hash_equals(trim((string)file_get_contents($dir.'/owner')),hash('sha256',session_id()))) v9_json(['ok'=>true,'upload_id'=>$resume,'resumed'=>true]);
    }
    $id=bin2hex(random_bytes(24));
    $dir=$base.DIRECTORY_SEPARATOR.hash('sha256',session_id().'|'.$id);
    mkdir($dir,0700,true); mkdir($dir.'/chunks',0700,true);
    file_put_contents($dir.'/owner',hash('sha256',session_id()),LOCK_EX);
    file_put_contents($dir.'/state.json',json_encode(['created'=>time(),'chunk_size'=>BrowserV9::CHUNK_SIZE,'chunks'=>[]],JSON_THROW_ON_ERROR),LOCK_EX);
    v9_json(['ok'=>true,'upload_id'=>$id,'resumed'=>false]);
  }
  $id=(string)($_GET['id']??'');
  if(!v9_hex($id,48)) v9_json(['ok'=>false,'error'=>'Invalid upload identifier.'],400);
  $dir=$base.DIRECTORY_SEPARATOR.hash('sha256',session_id().'|'.$id);
  if(!is_dir($dir)||!is_file($dir.'/owner')||!hash_equals(trim((string)file_get_contents($dir.'/owner')),hash('sha256',session_id()))) v9_json(['ok'=>false,'error'=>'Upload not found.'],404);
  if($action==='status') {
    $state=json_decode((string)file_get_contents($dir.'/state.json'),true,512,JSON_THROW_ON_ERROR);
    v9_json(['ok'=>true,'chunks'=>array_keys((array)($state['chunks']??[]))]);
  }
  if($action==='chunk') {
    $cid=(string)($_SERVER['HTTP_X_CHUNK_ID']??''); $fid=(string)($_SERVER['HTTP_X_FILE_ID']??''); $idx=(string)($_SERVER['HTTP_X_CHUNK_INDEX']??'');
    if(!v9_hex($cid,64)||!v9_hex($fid,32)||!ctype_digit($idx)) v9_json(['ok'=>false,'error'=>'Invalid chunk metadata.'],400);
    $data=file_get_contents('php://input');
    if($data===false || strlen($data)>BrowserV9::CHUNK_SIZE+64) v9_json(['ok'=>false,'error'=>'Invalid chunk body.'],400);
    $expected=hash('sha256','SECURE-BROWSER-V9|CHUNK|'.$data);
    if(!hash_equals($cid,$expected)) v9_json(['ok'=>false,'error'=>'Chunk integrity check failed.'],400);
    $path=$dir.'/chunks/'.$cid;
    if(!is_file($path)) file_put_contents($path,$data,LOCK_EX);
    $lock=fopen($dir.'/state.lock','c'); flock($lock,LOCK_EX);
    try {
      $state=json_decode((string)file_get_contents($dir.'/state.json'),true,512,JSON_THROW_ON_ERROR);
      $state['chunks'][$cid]=['file_id'=>$fid,'index'=>(int)$idx,'size'=>strlen($data)];
      file_put_contents($dir.'/state.json',json_encode($state,JSON_THROW_ON_ERROR),LOCK_EX);
    } finally { flock($lock,LOCK_UN); fclose($lock); }
    v9_json(['ok'=>true,'id'=>$cid]);
  }
  if($action==='finalize') {
    $d=v9_body(); $pkg=(string)($d['package_id']??'');
    if(!BrowserV9::validPackageId($pkg)||$pkg!==$id||!is_string($d['header']??null)||!is_string($d['manifest']??null)||!is_array($d['chunk_ids']??null)||count($d['chunk_ids'])>100000) v9_json(['ok'=>false,'error'=>'Invalid finalize request.'],400);
    $ids=[]; foreach($d['chunk_ids'] as $cid){ if(!is_string($cid)||!v9_hex($cid,64)||isset($ids[$cid])) v9_json(['ok'=>false,'error'=>'Invalid chunk inventory.'],400); $ids[$cid]=true; if(!is_file($dir.'/chunks/'.$cid)) v9_json(['ok'=>false,'error'=>'Missing encrypted chunk.'],400); }
    $header=base64_decode($d['header'],true); $manifest=base64_decode($d['manifest'],true);
    if($header===false||$manifest===false||strlen($header)>1048576||strlen($manifest)>52428800) v9_json(['ok'=>false,'error'=>'Invalid encrypted metadata.'],400);
    $h=json_decode($header,true);
    if(!is_array($h)||($h['format']??null)!==BrowserV9::FORMAT||(int)($h['version']??0)!==BrowserV9::VERSION||($h['package_id']??null)!==$pkg||($h['chunk_size']??null)!==BrowserV9::CHUNK_SIZE||($h['nonce_derivation']??null)!=='HMAC-SHA-256') v9_json(['ok'=>false,'error'=>'Invalid encrypted header.'],400);
    $out=$base.'/packages'; mkdir($out,0700,true); $pkgdir=$out.'/'.$pkg; if(is_dir($pkgdir)) v9_json(['ok'=>false,'error'=>'Package already exists.'],409); mkdir($pkgdir.'/chunks',0700,true);
    file_put_contents($pkgdir.'/header.bin',$header,LOCK_EX); file_put_contents($pkgdir.'/manifest.bin',$manifest,LOCK_EX);
    foreach(array_keys($ids) as $cid) rename($dir.'/chunks/'.$cid,$pkgdir.'/chunks/'.$cid);
    file_put_contents($pkgdir.'/inventory.json',json_encode(['package_id'=>$pkg,'chunk_ids'=>array_keys($ids),'merkle_root'=>(string)($d['merkle_root']??'')],JSON_THROW_ON_ERROR),LOCK_EX);
    file_put_contents($pkgdir.'/created',date('c'),LOCK_EX);
    @unlink($dir.'/owner'); @unlink($dir.'/state.json'); @unlink($dir.'/state.lock'); @rmdir($dir.'/chunks'); @rmdir($dir);
    v9_json(['ok'=>true,'package_id'=>$pkg]);
  }
  v9_json(['ok'=>false,'error'=>'Unknown action.'],404);
} catch(Throwable){ v9_json(['ok'=>false,'error'=>'Request failed.'],400); }
