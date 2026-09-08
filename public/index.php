<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
use TCH\Security\WebSecurity;
WebSecurity::startSession();
$csrf = WebSecurity::csrfToken();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCH Secure Package V2</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:#182230;background:#eef4fb}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#ffffff,#edf3fb 45%,#e5edf7)}main{max-width:980px;margin:48px auto;padding:24px}.card{background:rgba(255,255,255,.72);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.8);box-shadow:0 18px 50px rgba(24,50,80,.12);border-radius:24px;padding:28px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:760px){.grid{grid-template-columns:1fr}}label{display:block;font-weight:700;margin:10px 0 7px}input,button{width:100%;padding:13px 14px;border-radius:13px;border:1px solid #ccd7e4;font:inherit}input[type=file]{padding:10px;background:white}button{margin-top:18px;border:0;background:#1769e0;color:#fff;font-weight:800;cursor:pointer}button.secondary{background:#e9f0f8;color:#1c2e43}pre{white-space:pre-wrap;background:#101923;color:#dfeeff;border-radius:14px;padding:16px;min-height:80px}.muted{color:#657386}.status{margin-top:20px}.hidden{display:none}.pill{display:inline-block;padding:6px 10px;border-radius:999px;background:#e8f2ff;color:#1769e0;font-weight:700}
</style>
</head>
<body>
<main>
<div class="card">
<h1>TCH Secure Package V2</h1>
<p class="muted">Authenticated package encryption with password-and-pattern derived keys.</p>
<div class="grid">
<section>
<h2>Create Package</h2>
<label for="archive">Source ZIP</label>
<input id="archive" type="file" accept=".zip,application/zip">
<button id="uploadBtn">Upload and Inspect</button>
<div id="createArea" class="hidden">
<label for="archivePassword">Current Archive Password</label>
<input id="archivePassword" type="password" autocomplete="off">
<button id="stepBtn" class="secondary">Open Pending Archive</button>
<label for="projectName">Unique Project Name</label>
<input id="projectName" type="text" maxlength="100" autocomplete="off">
<label for="password">Encryption Password</label>
<input id="password" type="password" autocomplete="new-password">
<label for="pattern">Encryption Pattern</label>
<input id="pattern" type="password" autocomplete="new-password">
<button id="buildBtn">Build Encrypted Package</button>
</div>
</section>
<section>
<h2>Open Package</h2>
<label for="packageId">Package ID</label>
<input id="packageId" type="text" placeholder="36-character package ID">
<label for="decryptPassword">Password</label>
<input id="decryptPassword" type="password" autocomplete="off">
<label for="decryptPattern">Pattern</label>
<input id="decryptPattern" type="password" autocomplete="off">
<button id="decryptBtn">Open Package</button>
<p class="muted">Wrong credentials are intentionally reported as a generic package-open failure.</p>
</section>
</div>
<div class="status"><span class="pill" id="statusPill">Ready</span><pre id="log"></pre></div>
</div>
</main>
<script>
const csrf=<?php echo json_encode($csrf, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
let jobId=null,pendingId=null;
const $=id=>document.getElementById(id); const log=v=>$('log').textContent=typeof v==='string'?v:JSON.stringify(v,null,2); const status=v=>$('statusPill').textContent=v;
async function json(url,options={}){const r=await fetch(url,{...options,headers:{...(options.headers||{}),'X-CSRF-Token':csrf}}); const d=await r.json(); if(!r.ok||d.ok===false) throw new Error(d.error||'Request failed'); return d;}
$('uploadBtn').onclick=async()=>{try{const f=$('archive').files[0]; if(!f) throw new Error('Select a ZIP archive.'); const fd=new FormData(); fd.append('archive',f); const d=await json('api.php?action=upload',{method:'POST',body:fd}); jobId=d.job_id; pendingId=d.state.pending[0]?.id||null; $('createArea').classList.remove('hidden'); status(d.state.status); log(d.state)}catch(e){status('Error');log(e.message)}};
$('stepBtn').onclick=async()=>{try{if(!jobId||!pendingId) throw new Error('No pending archive.'); const d=await json('api.php?action=archive-step',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:jobId,archive_id:pendingId,password:$('archivePassword').value})}); pendingId=d.state.pending[0]?.id||null; $('archivePassword').value=''; status(d.state.status); log(d.state)}catch(e){status('Password Required');log(e.message)}};
$('buildBtn').onclick=async()=>{try{const d=await json('api.php?action=build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:jobId,project_name:$('projectName').value,password:$('password').value,pattern:$('pattern').value})}); status('Package Created'); log(d); if(d.download) log(JSON.stringify(d)+'\n\nDownload: '+d.download)}catch(e){status('Build Failed');log(e.message)}};
$('decryptBtn').onclick=async()=>{try{const d=await json('api.php?action=decrypt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:$('packageId').value,password:$('decryptPassword').value,pattern:$('decryptPattern').value})}); status('Package Opened'); log(d)}catch(e){status('Unable to Open Package');log(e.message)}};
</script>
</body>
</html>
