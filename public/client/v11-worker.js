'use strict';
const sessions = new Map();
const te = new TextEncoder();
const TTL = 10 * 60 * 1000;
const b = v => v instanceof Uint8Array ? v : new Uint8Array(v);
const text = v => typeof v === 'string' ? te.encode(v) : b(v);
const concat = (...parts) => { const n=parts.reduce((x,p)=>x+b(p).length,0),o=new Uint8Array(n); let i=0; for(const p0 of parts){const p=b(p0);o.set(p,i);i+=p.length;} return o; };
const hex = a => [...b(a)].map(x=>x.toString(16).padStart(2,'0')).join('');
const b64 = x => { const a=b(x); let s=''; for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode(...a.subarray(i,i+0x8000)); return btoa(s); };
const unb64 = s => { const x=atob(s),o=new Uint8Array(x.length); for(let i=0;i<x.length;i++)o[i]=x.charCodeAt(i); return o; };
const rand = n => crypto.getRandomValues(new Uint8Array(n));
async function digest(v){return new Uint8Array(await crypto.subtle.digest('SHA-256',b(v)));}
async function pbkdf(secret,salt,iterations){
  const key=await crypto.subtle.importKey('raw',text(secret),'PBKDF2',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations,hash:'SHA-256'},key,256));
}
async function hkdfRaw(ikm,salt,info,length=32){
  const base=await crypto.subtle.importKey('raw',b(ikm),'HKDF',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:b(salt),info:text(info)},base,length*8));
}
async function credentialWrapKey(password,pattern,salt,iterations){
  const pSalt=await digest(concat(text('SecurePackage|V11|PBKDF2|password|'),salt));
  const qSalt=await digest(concat(text('SecurePackage|V11|PBKDF2|pattern|'),salt));
  const p=await pbkdf(password,pSalt,iterations), q=await pbkdf(pattern,qSalt,iterations);
  try { return await hkdfRaw(concat(p,q),salt,'SecurePackage|V11|credential-wrap'); }
  finally { p.fill(0); q.fill(0); }
}
async function recoveryWrapKey(recovery,salt,iterations){
  const rSalt=await digest(concat(text('SecurePackage|V11|PBKDF2|recovery|'),salt));
  return await pbkdf(recovery,rSalt,iterations);
}
async function aesKey(raw,usage=['encrypt','decrypt']){return crypto.subtle.importKey('raw',b(raw),{name:'AES-GCM'},false,usage);}
async function hkdfKey(root,info,usage=['encrypt','decrypt']){
  const base=await crypto.subtle.importKey('raw',b(root),'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:text(info)},base,{name:'AES-GCM',length:256},false,usage);
}
async function wrap(root,wrapRaw,aad){const iv=rand(12),key=await aesKey(wrapRaw);const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text(aad)},key,root));return {iv:b64(iv),value:b64(ct)};}
async function unwrap(slot,wrapRaw,aad){const key=await aesKey(wrapRaw);return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(slot.iv),additionalData:text(aad)},key,unb64(slot.value)));}
async function nonce(root,ctx){const k=await crypto.subtle.importKey('raw',b(await hkdfRaw(root,new Uint8Array(32),'SecurePackage|V11|nonce-key')),{name:'HMAC',hash:'SHA-256'},false,['sign']);return (await crypto.subtle.sign('HMAC',k,text(ctx))).slice(0,12)}
function cleanup(){const now=Date.now();for(const [id,s] of sessions)if(s.expires<now){s.root.fill(0);sessions.delete(id)}}
self.onmessage=async e=>{
  cleanup(); const {id,op}=e.data||{};
  try {
    if(op==='createSession'){
      const salt=b(e.data.salt); const root=b(e.data.contentRoot); const wrapRaw=await credentialWrapKey(e.data.password,e.data.pattern,salt,e.data.iterations);
      const idv=hex(rand(16)); sessions.set(idv,{root:new Uint8Array(root),wrapRaw,expires:Date.now()+TTL,iterations:e.data.iterations,salt:new Uint8Array(salt)});
      self.postMessage({id,ok:true,result:{sessionId:idv}}); return;
    }
    if(op==='unlockSession'){
      const salt=b(e.data.salt), wrapRaw=await credentialWrapKey(e.data.password,e.data.pattern,salt,e.data.iterations);
      const root=await unwrap(e.data.slot,wrapRaw,`SecurePackage|V11|slot|primary|${e.data.packageId}`);
      if(root.length!==32)throw Error('Invalid content key.');
      const idv=hex(rand(16)); sessions.set(idv,{root,wrapRaw,expires:Date.now()+TTL,iterations:e.data.iterations,salt:new Uint8Array(salt)});
      self.postMessage({id,ok:true,result:{sessionId:idv}}); return;
    }
    if(op==='unlockRecovery'){
      const salt=b(e.data.salt), wrapRaw=await recoveryWrapKey(e.data.recovery,salt,e.data.iterations);
      const root=await unwrap(e.data.slot,wrapRaw,`SecurePackage|V11|slot|recovery|${e.data.packageId}`);
      if(root.length!==32)throw Error('Invalid content key.');
      const idv=hex(rand(16)); sessions.set(idv,{root,wrapRaw,expires:Date.now()+TTL,iterations:e.data.iterations,salt:new Uint8Array(salt)});
      self.postMessage({id,ok:true,result:{sessionId:idv}}); return;
    }
    if(op==='wrapCredential'){
      const wrapRaw=await credentialWrapKey(e.data.password,e.data.pattern,b(e.data.salt),e.data.iterations);
      const slot=await wrap(b(e.data.contentRoot),wrapRaw,`SecurePackage|V11|slot|primary|${e.data.packageId}`);
      wrapRaw.fill(0); self.postMessage({id,ok:true,result:slot}); return;
    }
    if(op==='wrapRecovery'){
      const wrapRaw=await recoveryWrapKey(e.data.recovery,b(e.data.salt),e.data.iterations);
      const slot=await wrap(b(e.data.contentRoot),wrapRaw,`SecurePackage|V11|slot|recovery|${e.data.packageId}`);
      wrapRaw.fill(0); self.postMessage({id,ok:true,result:slot}); return;
    }
    if(op==='rewrapCredential'){
      const s=sessions.get(e.data.sessionId); if(!s)throw Error('Session expired.');
      const wrapRaw=await credentialWrapKey(e.data.password,e.data.pattern,s.salt,e.data.iterations);
      const slot=await wrap(s.root,wrapRaw,`SecurePackage|V11|slot|primary|${e.data.packageId}`); wrapRaw.fill(0); self.postMessage({id,ok:true,result:slot}); return;
    }
    if(op==='nonce'){
      const s=sessions.get(e.data.sessionId); if(!s)throw Error('Session expired.'); s.expires=Date.now()+TTL; const iv=await nonce(s.root,e.data.context); self.postMessage({id,ok:true,result:iv},[iv]); return;
    }
    if(op==='crypt'){
      const s=sessions.get(e.data.sessionId); if(!s)throw Error('Session expired.'); s.expires=Date.now()+TTL;
      const rawKey=await hkdfRaw(s.root,new Uint8Array(32),`SecurePackage|V11|key|${e.data.purpose}|${e.data.context||''}`);
      const key=await aesKey(rawKey); rawKey.fill(0);
      const out=e.data.mode==='enc'?await crypto.subtle.encrypt({name:'AES-GCM',iv:b(e.data.iv),additionalData:text(e.data.aad||'')},key,b(e.data.data)):await crypto.subtle.decrypt({name:'AES-GCM',iv:b(e.data.iv),additionalData:text(e.data.aad||'')},key,b(e.data.data));
      self.postMessage({id,ok:true,result:out},[out]); return;
    }
    if(op==='hash'){const out=await digest(e.data.data);self.postMessage({id,ok:true,result:out},[out]);return;}
    if(op==='destroy'){const s=sessions.get(e.data.sessionId);if(s){s.root.fill(0);s.wrapRaw.fill(0);sessions.delete(e.data.sessionId);}self.postMessage({id,ok:true,result:true});return;}
    throw Error('Unsupported operation.');
  } catch(_) { self.postMessage({id,ok:false,error:'Client cryptographic operation failed.'}); }
};
