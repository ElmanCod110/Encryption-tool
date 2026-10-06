const state = { csrf: document.querySelector('meta[name="csrf-token"]')?.content || '', jobId: null, pendingId: null, authMode: 'login' };
const $ = (id) => document.getElementById(id);
const log = (value) => { $('log').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); };
const setStatus = (value) => { $('statusPill').textContent = value; $('createState').textContent = value; };
const formatBytes = (n) => { if (!n) return '0 B'; const u=['B','KB','MB','GB']; const i=Math.min(Math.floor(Math.log(n)/Math.log(1024)),3); return `${(n/Math.pow(1024,i)).toFixed(i?1:0)} ${u[i]}`; };
async function api(action, options={}) {
  const headers = { ...(options.headers || {}), 'X-CSRF-Token': state.csrf };
  const response = await fetch(`api.php?action=${encodeURIComponent(action)}`, { ...options, headers, credentials: 'same-origin' });
  let payload = {};
  try { payload = await response.json(); } catch (_) {}
  if (!response.ok || payload.ok === false) throw new Error(payload.error || 'Request failed.');
  if (payload.csrf) state.csrf = payload.csrf;
  return payload;
}
function strength(input, output) { const n = Math.min(100, Math.round((input.value.length / 20) * 100)); $(output).style.width = `${n}%`; }
function showSecret(inputId) { const input = $(inputId); input.type = input.type === 'password' ? 'text' : 'password'; }
$('showPassword').onclick = () => showSecret('password'); $('showPattern').onclick = () => showSecret('pattern');
$('password').oninput = () => strength($('password'), 'passwordStrength'); $('pattern').oninput = () => strength($('pattern'), 'patternStrength');

const zone = $('dropzone'); const fileInput = $('archive');
$('browseBtn').onclick = (e) => { e.stopPropagation(); fileInput.click(); };
zone.onclick = (e) => { if (!e.target.closest('button')) fileInput.click(); };
['dragenter','dragover'].forEach((name) => zone.addEventListener(name, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
['dragleave','drop'].forEach((name) => zone.addEventListener(name, (e) => { e.preventDefault(); zone.classList.remove('drag'); }));
zone.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; if (f) startUpload(f); });
fileInput.onchange = () => fileInput.files[0] && startUpload(fileInput.files[0]);

async function startUpload(file) {
  if (!/\.zip$/i.test(file.name)) { setStatus('ZIP required'); log('Please select a ZIP archive.'); return; }
  try {
    $('uploadProgress').classList.remove('hidden'); $('uploadProgressBar').style.width='0%'; $('uploadProgressText').textContent='0%'; $('uploadProgressSize').textContent=`0 / ${formatBytes(file.size)}`;
    const init = await api('upload-init', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ total_bytes:file.size }) });
    const upload = init.upload; const chunkSize = 4 * 1024 * 1024;
    for (let offset=0; offset<file.size; offset += chunkSize) {
      const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size));
      await api('upload-chunk', { method:'POST', headers:{'Content-Type':'application/octet-stream','X-Upload-ID':upload.id,'X-Upload-Offset':String(offset)}, body:chunk });
      const received = Math.min(offset + chunk.size, file.size); const pct = Math.round(received / file.size * 100);
      $('uploadProgressBar').style.width=`${pct}%`; $('uploadProgressText').textContent=`${pct}%`; $('uploadProgressSize').textContent=`${formatBytes(received)} / ${formatBytes(file.size)}`;
    }
    const complete = await api('upload-complete', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ upload_id:upload.id }) });
    state.jobId = complete.job_id; state.pendingId = complete.state.pending?.[0]?.id || null;
    $('createFlow').classList.remove('hidden'); $('buildFooter').classList.remove('hidden');
    $('archiveNotice').textContent = state.pendingId ? 'A protected archive is waiting for a password.' : 'All archives are processed.';
    setStatus(complete.state.status); log(complete.state);
  } catch (err) { setStatus('Upload failed'); log(err.message); }
}
$('stepBtn').onclick = async () => {
  try {
    if (!state.jobId || !state.pendingId) throw new Error('No protected archive is pending.');
    if ($('archivePassword').classList.contains('hidden')) { $('archivePassword').classList.remove('hidden'); $('archivePassword').focus(); $('stepBtn').textContent='Process protected archive'; return; }
    const d = await api('archive-step', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ job_id:state.jobId, archive_id:state.pendingId, password:$('archivePassword').value }) });
    state.pendingId = d.state.pending?.[0]?.id || null; $('archivePassword').value=''; $('archivePassword').classList.toggle('hidden', !state.pendingId); $('stepBtn').textContent = state.pendingId ? 'Process protected archive' : 'Done'; $('archiveNotice').textContent = state.pendingId ? 'Another protected archive is waiting for a password.' : 'All archives are processed.'; setStatus(d.state.status); log(d.state);
  } catch(err) { setStatus('Archive step failed'); log(err.message); }
};
$('buildBtn').onclick = async () => {
  try {
    if (!state.jobId) throw new Error('Upload a ZIP archive first.');
    const d = await api('build', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ job_id:state.jobId, project_name:$('projectName').value, password:$('password').value, pattern:$('pattern').value }) });
    log(d); setStatus('Package created'); $('packageId').value=d.package_id; addLink('Download encrypted package', d.download); loadPackages(); $('password').value=''; $('pattern').value='';
  } catch(err) { setStatus('Build failed'); log(err.message); }
};
$('decryptBtn').onclick = async () => {
  try { const d = await api('decrypt', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({package_id:$('packageId').value.trim(),password:$('decryptPassword').value,pattern:$('decryptPattern').value})}); setStatus('Package restored'); log(d); addLink('Download restored files', d.restore_download); $('decryptPassword').value=''; $('decryptPattern').value=''; }
  catch(err) { setStatus('Unable to open package'); log(err.message); }
};
function addLink(label, url) { const box=document.createElement('div'); box.style.marginTop='10px'; const a=document.createElement('a'); a.href=url; a.textContent=label; a.target='_blank'; a.rel='noopener'; a.style.color='#346fe5'; a.style.fontWeight='800'; a.style.fontSize='11px'; box.appendChild(a); $('log').appendChild(document.createTextNode(`\n${label}: ${url}`)); }

async function loadPackages() { try { const d=await api('packages',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); renderPackages(d.packages); } catch(err) { log(err.message); } }
function renderPackages(items) {
  const box=$('packageList'); if (!items.length) { box.className='package-list empty'; box.innerHTML='<div class="empty-icon"><svg viewBox="0 0 32 32"><path d="M5 9h8l2 3h12v13H5z"/><path d="M5 9V7h9l2 2"/></svg></div><strong>No managed packages</strong><span>Create a package or sign in to see managed items.</span>'; return; }
  box.className='package-list'; box.replaceChildren();
  items.slice(0,8).forEach(item=>{ const row=document.createElement('div'); row.className='pkg-row'; const meta=document.createElement('div'); meta.className='pkg-meta'; const strong=document.createElement('strong'); strong.textContent=item.package_id; const span=document.createElement('span'); span.textContent=item.revoked?'Revoked':`Created ${new Date(item.created_at*1000).toLocaleString()}`; meta.append(strong,span); const actions=document.createElement('div'); actions.className='pkg-actions'; const dl=document.createElement('button'); dl.textContent='Link'; dl.onclick=async()=>{try{const d=await api('access-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:item.package_id})}); window.open(d.download,'_blank','noopener');}catch(err){log(err.message);}}; const exp=document.createElement('button'); exp.textContent='Expiry'; exp.onclick=async()=>{const days=prompt('Expiration in days. Use 0 for no expiration.', item.expires_at?Math.max(1,Math.ceil((item.expires_at-Date.now()/1000)/86400)):0); if(days===null)return; try{await api('set-expiry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:item.package_id,expires_in:Number(days)*86400})}); loadPackages();}catch(err){log(err.message);}}; const rev=document.createElement('button'); rev.textContent='Revoke'; rev.disabled=item.revoked; rev.onclick=async()=>{if(!confirm('Revoke this package access?'))return; try{await api('revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:item.package_id})}); loadPackages();}catch(err){log(err.message);}}; actions.append(dl,exp,rev); row.append(meta,actions); box.appendChild(row); });
}
$('refreshPackages').onclick=loadPackages;

const modal=$('authModal'); const openAuth=()=>modal.classList.remove('hidden'); $('authButton').onclick=openAuth; $('closeAuth').onclick=()=>modal.classList.add('hidden');
$('loginTab').onclick=()=>switchAuth('login'); $('registerTab').onclick=()=>switchAuth('register');
function switchAuth(mode){state.authMode=mode; $('loginTab').classList.toggle('active',mode==='login'); $('registerTab').classList.toggle('active',mode==='register'); $('authTitle').textContent=mode==='login'?'Sign in':'Create account'; $('authSubmit').textContent=mode==='login'?'Sign in':'Create account'; $('authPassword').autocomplete=mode==='login'?'current-password':'new-password';}
$('authSubmit').onclick=async()=>{try{const action=state.authMode==='login'?'login':'register'; const d=await api(action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('authUsername').value,password:$('authPassword').value})}); $('authPassword').value=''; modal.classList.add('hidden'); $('authButton').textContent='Account'; log(d); loadPackages();}catch(err){log(err.message);}};
$('logoutButton').onclick=async()=>{try{const d=await api('logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); $('authButton').textContent='Sign in'; log(d);}catch(err){log(err.message);}};

(async()=>{try{const d=await api('me',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); if(d.authenticated){$('authButton').textContent='Account'; loadPackages();}}catch(_){}})();
