<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders(true);
$csrf = WebSecurity::csrfToken();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Package V3</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#182230;background:#edf3fa}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 10% 0%,#fff 0,#eef4fb 42%,#e4ecf6 100%)}main{max-width:1180px;margin:0 auto;padding:42px 22px 70px}.hero{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:22px}.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800;color:#527090}.hero h1{margin:5px 0 8px;font-size:42px;line-height:1}.hero p{margin:0;color:#647386;max-width:720px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.card{background:rgba(255,255,255,.72);backdrop-filter:blur(22px);border:1px solid rgba(255,255,255,.86);box-shadow:0 22px 70px rgba(27,55,89,.11);border-radius:26px;padding:24px}.card h2{margin:0 0 8px}.muted{color:#68788a;font-size:14px}.field{margin-top:15px}.field label{display:block;font-weight:750;font-size:14px;margin:0 0 7px}.row{display:grid;grid-template-columns:1fr auto;gap:10px}.row input{min-width:0}input,button{width:100%;padding:13px 14px;border-radius:14px;border:1px solid #cbd7e5;font:inherit;background:rgba(255,255,255,.88)}input:focus{outline:3px solid rgba(43,112,215,.15);border-color:#6b9ade}button{margin-top:16px;border:0;color:#fff;background:#216bd4;font-weight:800;cursor:pointer;box-shadow:0 9px 22px rgba(33,107,212,.2)}button.secondary{background:#edf3fa;color:#24405f;box-shadow:none;border:1px solid #d5e0ec}.status{margin-top:20px}.statusbar{display:flex;gap:10px;align-items:center}.pill{display:inline-flex;align-items:center;padding:7px 11px;border-radius:999px;background:#e9f3ff;color:#1762c5;font-weight:800;font-size:13px}.ok{background:#eaf8f0;color:#137540}.danger{background:#fff0ef;color:#a03931}pre{white-space:pre-wrap;word-break:break-word;background:#0d1622;color:#dbe8f8;border-radius:16px;padding:16px;min-height:170px;max-height:340px;overflow:auto}.hidden{display:none}.notice{margin-top:18px;padding:14px 16px;border-radius:16px;background:#f7fafc;border:1px solid #e1e9f1;color:#586a7d;font-size:13px}.meter{margin-top:9px;height:8px;border-radius:999px;background:#e9eef4;overflow:hidden}.meter span{display:block;height:100%;width:0;background:#6a92c9;transition:width .2s}.links{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap}.links a{color:#1762c5;font-weight:700;text-decoration:none}.tiny{font-size:12px;color:#8390a0}@media(max-width:820px){.grid{grid-template-columns:1fr}.hero{display:block}.hero h1{font-size:34px}.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<section class="hero">
<div>
<div class="eyebrow">Open-source encrypted package system</div>
<h1>Secure Package <span class="tiny">V3</span></h1>
<p>Authenticated encryption, encrypted manifests, randomized package layout, recursive archive handling, staged restoration, and credential-derived keys.</p>
</div>
</section>
<div class="grid">
<section class="card">
<h2>Create package</h2>
<p class="muted">Upload a ZIP archive. Protected or nested archives are processed one stage at a time.</p>
<div class="field"><label for="archive">Source ZIP archive</label><input id="archive" type="file" accept=".zip,application/zip"></div>
<button id="uploadBtn">Upload and inspect</button>
<div id="createArea" class="hidden">
<div class="notice" id="archiveNotice">No protected archive is pending.</div>
<div class="field"><label for="archivePassword">Archive password</label><input id="archivePassword" type="password" autocomplete="off"></div>
<button id="stepBtn" class="secondary">Process pending archive</button>
<div class="field"><label for="projectName">Unique project name</label><input id="projectName" type="text" maxlength="100" autocomplete="off"></div>
<div class="field"><label for="password">Encryption password</label><input id="password" type="password" autocomplete="new-password"><div class="meter"><span id="passwordMeter"></span></div></div>
<div class="field"><label for="pattern">Encryption pattern</label><input id="pattern" type="password" autocomplete="new-password"><div class="meter"><span id="patternMeter"></span></div></div>
<button id="buildBtn">Build encrypted package</button>
</div>
</section>
<section class="card">
<h2>Open package</h2>
<p class="muted">Only the package identifier, password, and pattern are used to derive the decryption key.</p>
<div class="field"><label for="packageId">Package ID</label><input id="packageId" type="text" inputmode="hexadecimal" maxlength="48" placeholder="48-character package ID"></div>
<div class="field"><label for="decryptPassword">Password</label><input id="decryptPassword" type="password" autocomplete="off"></div>
<div class="field"><label for="decryptPattern">Pattern</label><input id="decryptPattern" type="password" autocomplete="off"></div>
<button id="decryptBtn">Open package</button>
<div class="notice">Credential failures are intentionally reported generically. The server does not reveal whether the password or pattern was the failing input.</div>
</section>
</div>
<section class="card status">
<div class="statusbar"><span class="pill" id="statusPill">Ready</span><span class="tiny">Package operations are staged and temporary data is cleaned by TTL.</span></div>
<pre id="log">Waiting for an operation.</pre>
<div class="links" id="links"></div>
</section>
</main>
<script>
const csrf=<?php echo json_encode($csrf, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
let jobId=null,pendingId=null;
const $=id=>document.getElementById(id);
const log=v=>$('log').textContent=typeof v==='string'?v:JSON.stringify(v,null,2);
const status=v=>$('statusPill').textContent=v;
const link=(label,url)=>{const a=document.createElement('a');a.href=url;a.textContent=label;a.target='_blank';a.rel='noopener';$('links').appendChild(a)};
function meter(input,m){const v=input.value.length;$(m).style.width=Math.min(100,v*6)+'%';}
$('password').addEventListener('input',()=>meter($('password'),'passwordMeter'));
$('pattern').addEventListener('input',()=>meter($('pattern'),'patternMeter'));
async function json(url,options={}){const r=await fetch(url,{...options,headers:{...(options.headers||{}),'X-CSRF-Token':csrf}});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||'Request failed');return d;}
$('uploadBtn').onclick=async()=>{try{const f=$('archive').files[0];if(!f)throw new Error('Select a ZIP archive.');$('links').replaceChildren();const fd=new FormData();fd.append('archive',f);const d=await json('api.php?action=upload',{method:'POST',body:fd});jobId=d.job_id;pendingId=d.state.pending[0]?.id||null;$('createArea').classList.remove('hidden');status(d.state.status);$('archiveNotice').textContent=pendingId?'A protected archive is waiting for a password.':'No protected archive is pending.';log(d.state)}catch(e){status('Error');log(e.message)}};
$('stepBtn').onclick=async()=>{try{if(!jobId||!pendingId)throw new Error('No pending archive.');const d=await json('api.php?action=archive-step',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:jobId,archive_id:pendingId,password:$('archivePassword').value})});pendingId=d.state.pending[0]?.id||null;$('archivePassword').value='';$('archiveNotice').textContent=pendingId?'Another protected archive is waiting for a password.':'All archives are processed.';status(d.state.status);log(d.state)}catch(e){status('Archive step failed');log(e.message)}};
$('buildBtn').onclick=async()=>{try{if(!jobId)throw new Error('Upload and process an archive first.');const d=await json('api.php?action=build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:jobId,project_name:$('projectName').value,password:$('password').value,pattern:$('pattern').value})});status('Package created');log(d);$('password').value='';$('pattern').value='';if(d.download)link('Download encrypted package',d.download); }catch(e){status('Build failed');log(e.message)}};
$('decryptBtn').onclick=async()=>{try{const d=await json('api.php?action=decrypt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:$('packageId').value,password:$('decryptPassword').value,pattern:$('decryptPattern').value})});status('Package opened');log(d);if(d.restore_download)link('Download restored files',d.restore_download);$('decryptPassword').value='';$('decryptPattern').value='';}catch(e){status('Unable to open package');log(e.message)}};
</script>
</body>
</html>
