<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class UploadInventory
{
    public function __construct(private readonly string $root, private readonly int $ttl = 7200)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) throw new RuntimeException('Unable to initialize inventory storage.');
    }

    public function create(string $ownerId, string $packageId, int $expectedChunks, int $expectedBytes): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) throw new RuntimeException('Invalid package identifier.');
        if ($expectedChunks < 1 || $expectedChunks > 10000000 || $expectedBytes < 1) throw new RuntimeException('Invalid upload declaration.');
        $id = bin2hex(random_bytes(24)); $dir = $this->dir($id);
        if (!mkdir($dir, 0700, true)) throw new RuntimeException('Unable to create upload session.');
        AtomicFile::write($dir . '/state.json', json_encode(['id'=>$id,'owner_hash'=>hash('sha256',$ownerId),'package_id'=>$packageId,'expected_chunks'=>$expectedChunks,'expected_bytes'=>$expectedBytes,'received_chunks'=>0,'received_bytes'=>0,'created_at'=>time(),'finalized'=>false], JSON_THROW_ON_ERROR));
        touch($dir . '/lock');
        return $this->state($id, $ownerId);
    }

    public function state(string $id, string $ownerId): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $id)) throw new RuntimeException('Upload does not exist.');
        $file = $this->dir($id) . '/state.json'; if (!is_file($file)) throw new RuntimeException('Upload does not exist.');
        $state = json_decode((string)file_get_contents($file), true, 32, JSON_THROW_ON_ERROR);
        if (!hash_equals((string)$state['owner_hash'], hash('sha256',$ownerId))) throw new RuntimeException('Upload does not exist.');
        if (time() - (int)$state['created_at'] > $this->ttl) throw new RuntimeException('Upload expired.');
        return $state;
    }

    public function markChunk(string $id, string $ownerId, string $chunkId, int $bytes): array
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $chunkId) || $bytes < 1) throw new RuntimeException('Invalid chunk declaration.');
        $dir=$this->dir($id); $lock=fopen($dir.'/lock','c+b'); if($lock===false||!flock($lock,LOCK_EX)) throw new RuntimeException('Unable to lock upload.');
        try { $s=$this->state($id,$ownerId); if($s['finalized']) throw new RuntimeException('Upload already finalized.'); $indexFile=$dir.'/chunks.jsonl';
            $known=false; if(is_file($indexFile)){foreach(file($indexFile,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){$x=json_decode($line,true);if(is_array($x)&&($x['id']??'')===$chunkId){$known=true;break;}}}
            if(!$known){file_put_contents($indexFile,json_encode(['id'=>$chunkId,'bytes'=>$bytes],JSON_THROW_ON_ERROR)."\n",FILE_APPEND|LOCK_EX);$s['received_chunks']++;$s['received_bytes']+=$bytes;AtomicFile::write($dir.'/state.json',json_encode($s,JSON_THROW_ON_ERROR));}
            return $s;
        } finally {flock($lock,LOCK_UN);fclose($lock);}
    }

    public function inventory(string $id,string $ownerId): array { $s=$this->state($id,$ownerId);$out=[];$f=$this->dir($id).'/chunks.jsonl';if(is_file($f))foreach(file($f,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){$x=json_decode($line,true);if(is_array($x)&&isset($x['id']))$out[]=$x['id'];}return ['state'=>$s,'chunks'=>$out]; }
    public function finalize(string $id,string $ownerId): array { $s=$this->state($id,$ownerId);if($s['received_chunks']!==$s['expected_chunks']||$s['received_bytes']!==$s['expected_bytes'])throw new RuntimeException('Upload inventory is incomplete.');$s['finalized']=true;AtomicFile::write($this->dir($id).'/state.json',json_encode($s,JSON_THROW_ON_ERROR));return $s; }
    private function dir(string $id): string{return $this->root.DIRECTORY_SEPARATOR.$id;}
}
