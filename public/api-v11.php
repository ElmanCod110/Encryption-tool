<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SecurePackage\Client\V11Descriptor;
use SecurePackage\Security\WebSecurity;
use SecurePackage\Storage\ChunkStore;
use SecurePackage\Storage\UploadInventory;
WebSecurity::startSession(); WebSecurity::applyHeaders(true);
$config=require dirname(__DIR__).'/config/config.php';
$chunkStore=new ChunkStore($config['storage']['chunks'],16*1024*1024);
$inventory=new UploadInventory($config['storage']['upload_inventory'],7200);
function v11_json(array $d,int $s=200):never{http_response_code($s);header('Content-Type: application/json; charset=utf-8');echo json_encode($d,JSON_UNESCAPED_SLASHES);exit;}
function v11_body():array{$raw=file_get_contents('php://input');$d=json_decode($raw?:'{}',true);return is_array($d)?$d:[];}
function v11_csrf():void{$p=(string)($_SERVER['HTTP_X_CSRF_TOKEN']??'');if(!hash_equals(WebSecurity::csrfToken(),$p))v11_json(['ok'=>false,'error'=>'Invalid request token.'],403);}
$action=(string)($_GET['action']??''); if($action==='csrf')v11_json(['ok'=>true,'csrf'=>WebSecurity::csrfToken()]); v11_csrf();
try{
 if($action==='descriptor')v11_json(['ok'=>true,'descriptor'=>V11Descriptor::descriptor()]);
 if($action==='init'){$d=v11_body();$pkg=(string)($d['package_id']??'');$count=(int)($d['expected_chunks']??0);$bytes=(int)($d['expected_bytes']??0);if(!V11Descriptor::validPackageId($pkg))v11_json(['ok'=>false,'error'=>'Invalid package identifier.'],400);$s=$inventory->create(session_id(),$pkg,$count,$bytes);v11_json(['ok'=>true,'upload'=>$s]);}
 $id=(string)($_GET['id']??''); if(!preg_match('/^[a-f0-9]{48}$/',$id))v11_json(['ok'=>false,'error'=>'Invalid upload identifier.'],400);
 if($action==='status')v11_json(['ok'=>true]+$inventory->inventory($id,session_id()));
 if($action==='chunk'){$cid=(string)($_SERVER['HTTP_X_CHUNK_ID']??'');if(!preg_match('/^[a-f0-9]{64}$/',$cid))v11_json(['ok'=>false,'error'=>'Invalid chunk identifier.'],400);$body=file_get_contents('php://input');if($body===false||strlen($body)>16*1024*1024)v11_json(['ok'=>false,'error'=>'Chunk is too large.'],413);$chunkStore->put($cid,$body);$state=$inventory->markChunk($id,session_id(),$cid,strlen($body));v11_json(['ok'=>true,'state'=>$state]);}
 if($action==='finalize'){$s=$inventory->finalize($id,session_id());$dir=$config['storage']['packages'].'/v11';@mkdir($dir,0700,true);$meta=['upload_id'=>$id,'package_id'=>$s['package_id'],'expected_chunks'=>$s['expected_chunks'],'expected_bytes'=>$s['expected_bytes'],'finalized_at'=>gmdate('c')];file_put_contents($dir.'/'.$s['package_id'].'.json',json_encode($meta,JSON_THROW_ON_ERROR),LOCK_EX);v11_json(['ok'=>true,'package_id'=>$s['package_id'],'state'=>$s]);}
 v11_json(['ok'=>false,'error'=>'Unknown action.'],404);
}catch(Throwable){v11_json(['ok'=>false,'error'=>'Request failed.'],400);}
