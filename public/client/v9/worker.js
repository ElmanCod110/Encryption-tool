'use strict';
const sessions = new Map();
const te = new TextEncoder();
const TTL = 5 * 60 * 1000;
const b = v => v instanceof Uint8Array ? v : new Uint8Array(v);
const text = v => typeof v === 'string' ? te.encode(v) : b(v);
const hex = a => [...b(a)].map(x => x.toString(16).padStart(2, '0')).join('');
const concat = (...parts) => { const n=parts.reduce((x,p)=>x+b(p).length,0),o=new Uint8Array(n);let i=0;for(const p0 of parts){const p=b(p0);o.set(p,i);i+=p.length;}return o; };
function cleanup(){const now=Date.now();for(const [id,s] of sessions)if(s.expires<=now)sessions.delete(id)}
async function derive(password,pattern,salt,iterations){
  const ps=await crypto.subtle.digest('SHA-256',concat(text('SecurePackage|V9|password|salt|'),salt));
  const qs=await crypto.subtle.digest('SHA-256',concat(text('SecurePackage|V9|pattern|salt|'),salt));
  const pk=await crypto.subtle.importKey('raw',text(password),'PBKDF2',false,['deriveBits']);
  const qk=await crypto.subtle.importKey('raw',text(pattern),'PBKDF2',false,['deriveBits']);
  const a=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new Uint8Array(ps),iterations,hash:'SHA-256'},pk,256);
  const c=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new Uint8Array(qs),iterations,hash:'SHA-256'},qk,256);
  const root=await crypto.subtle.importKey('raw',concat(new Uint8Array(a),new Uint8Array(c)),'HKDF',false,['deriveKey']);
  const make=label=>crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:text(`SecurePackage|V9|key|${label}`)},root,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const nonceKey=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:text('SecurePackage|V9|nonce')},root,{name:'HMAC',hash:'SHA-256',length:256},false,['sign']);
  return {manifest:await make('manifest'),filename:await make('filename'),file:await make('file'),nonceKey};
}
const getKey=(s,p)=>p==='manifest'?s.manifest:p==='filename'?s.filename:p==='file'?s.file:null;
self.onmessage=async e=>{cleanup();const {id,op}=e.data||{};try{
  if(op==='start'){const keys=await derive(e.data.password,e.data.pattern,b(e.data.salt),e.data.iterations);const sid=hex(crypto.getRandomValues(new Uint8Array(16)));sessions.set(sid,{...keys,expires:Date.now()+TTL});self.postMessage({id,ok:true,result:{sessionId:sid}});return}
  if(op==='destroy'){sessions.delete(e.data.sessionId);self.postMessage({id,ok:true,result:true});return}
  const s=sessions.get(e.data.sessionId);if(!s)throw Error('Session expired.');s.expires=Date.now()+TTL;
  if(op==='hash'){const out=await crypto.subtle.digest('SHA-256',b(e.data.data));self.postMessage({id,ok:true,result:out},[out]);return}
  if(op==='nonce'){const mac=await crypto.subtle.sign('HMAC',s.nonceKey,text(e.data.context));const iv=new Uint8Array(mac).slice(0,12);self.postMessage({id,ok:true,result:iv},[iv.buffer]);return}
  if(op==='crypt'){const k=getKey(s,e.data.purpose);if(!k)throw Error('Unsupported key purpose.');const out=e.data.mode==='enc'?await crypto.subtle.encrypt({name:'AES-GCM',iv:b(e.data.iv),additionalData:text(e.data.aad||'')},k,b(e.data.data)):await crypto.subtle.decrypt({name:'AES-GCM',iv:b(e.data.iv),additionalData:text(e.data.aad||'')},k,b(e.data.data));self.postMessage({id,ok:true,result:out},[out]);return}
  throw Error('Unsupported operation.');
}catch(_){self.postMessage({id,ok:false,error:'Client cryptographic operation failed.'})}};
