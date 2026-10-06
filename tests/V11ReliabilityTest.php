<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SecurePackage\Client\MerkleAccumulator;
use SecurePackage\Client\V11Descriptor;
use SecurePackage\Storage\ChunkStore;
use SecurePackage\Storage\UploadInventory;
$root=sys_get_temp_dir().'/sp-v11-'.bin2hex(random_bytes(5));@mkdir($root,0700,true);
try{
 if(V11Descriptor::MAGIC!=='SPK11BIN1'||V11Descriptor::VERSION!==11)throw new RuntimeException('Descriptor failed.');
 $m=new MerkleAccumulator();$leaves=[];for($i=0;$i<7;$i++){ $leaf=hash('sha256','leaf-'.$i);$m->push($leaf);$leaves[]=$leaf; }
 if($m->count()!==7||!preg_match('/^[a-f0-9]{64}$/',$m->root()))throw new RuntimeException('Merkle accumulator failed.');
 $chunks=new ChunkStore($root.'/chunks');$data=random_bytes(4096);$id=hash('sha256',$data);if(!$chunks->put($id,$data)||$chunks->put($id,$data)!==false||$chunks->get($id)!==$data)throw new RuntimeException('Chunk store failed.');
 $inv=new UploadInventory($root.'/uploads');$s=$inv->create('owner','abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',2,12);$inv->markChunk($s['id'],'owner',hash('sha256','aaaa'),4);$inv->markChunk($s['id'],'owner',hash('sha256','bbbb'),8);$final=$inv->finalize($s['id'],'owner');if(!$final['finalized'])throw new RuntimeException('Upload finalize failed.');
 echo "V11 reliability tests passed.\n";
}finally{if(is_dir($root)){foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $f){$f->isDir()?@rmdir($f->getPathname()):@unlink($f->getPathname());}@rmdir($root);}}
