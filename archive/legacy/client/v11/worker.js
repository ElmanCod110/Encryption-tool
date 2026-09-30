'use strict';
const sessions=new Map(),te=new TextEncoder();
const b=v=>v instanceof Uint8Array?v:new Uint8Array(v),text=v=>typeof v==='string'?te.encode(v):b(v);
const concat=(...ps)=>{const n=ps.reduce((x,p)=>x+b(p).length,0),o=new Uint8Array(n);let i=0;for(const p0 of ps){const p=b(p0);o.set(p,i);i+=p.length}return o};
const hex=a=>[...b(a)].map(x=>x.toString(16).padStart(2,'0')).join('');
const b64=x=>{const a=b(x);let s='';for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode(...a.subarray(i,i+0x8000));return btoa(s)};
const unb64=s=>{const x=atob(s),o=new Uint8Array(x.length);for(let i=0;i<x.length;i++)o[i]=x.charCodeAt(i);return o};
const rand=n=>crypto.getRandomValues(new Uint8Array(n));
async function digest(v){return new Uint8Array(await crypto.subtle.digest('SHA-256',b(v)))}
async function pbkdf(secret,salt,iterations){const k=await crypto.subtle.importKey('raw',text(secret),'PBKDF2',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations,hash:'SHA-256'},k,256))}
async function hkdf(ikm,salt,info,len=32){const k=await crypto.subtle.importKey('raw',b(ikm),'HKDF',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:b(salt),info:text(info)},k,len*8))}
async function credentialKey(password,pattern,salt,it){const ps=await digest(concat(text('SecurePackage|V11|PBKDF2|password|'),salt)),qs=await digest(concat(text('SecurePackage|V11|PBKDF2|pattern|'),salt));const p=await pbkdf(password,ps,it),q=await pbkdf(pattern,qs,it);try{return hkdf(concat(p,q),salt,'SecurePackage|V11|credential-wrap')}finally{p.fill(0);q.fill(0)}}
async function recoveryKey(recovery,salt,it){const rs=await digest(concat(text('SecurePackage|V11|PBKDF2|recovery|'),salt));return pbkdf(recovery,rs,it)}
async function aes(raw,usage=['encrypt','decrypt']){return crypto.subtle.importKey('raw',b(raw),{name:'AES-GCM'},false,usage)}
async function wrap(root,key,aad){const iv=rand(12),k=await aes(key);const value=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text(aad)},k,root));return{iv:b64(iv),value:b64(value)}}
async function unwrap(slot,key,aad){const k=await aes(key);return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(slot.iv),additionalData:text(aad)},k,unb64(slot.value)))}
async function nonce(root,ctx){const nk=await hkdf(root,new Uint8Array(32),'SecurePackage|V11|nonce-domain');const k=await crypto.subtle.importKey('raw',nk,{name:'HMAC',hash:'SHA-256'},false,['sign']);nk.fill(0);return new Uint8Array((await crypto.subtle.sign('HMAC',k,text(ctx))).slice(0,12))}
async function crypt(s,purpose,context,iv,data,aad,mode){const raw=await hkdf(s.root,new Uint8Array(32),`SecurePackage|V11|key|${purpose}|${context}`);const k=await aes(raw);raw.fill(0);const out=mode==='enc'?await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text(aad)},k,b(data)):await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:text(aad)},k,b(data));return new Uint8Array(out)}
function session(sid){const s=sessions.get(sid);if(!s)throw Error('Session expired.');s.expires=Date.now()+10*60*1000;return s}
self.onmessage=async e=>{const{id,op}=e.data||{};try{
 if(op==='createSession'){const salt=b(e.data.salt),root=b(e.data.root),wk=await credentialKey(e.data.password,e.data.pattern,salt,e.data.iterations);const sid=hex(rand(16));sessions.set(sid,{root:new Uint8Array(root),wrapRaw:wk,salt:new Uint8Array(salt),expires:Date.now()+600000});self.postMessage({id,ok:true,result:{sessionId:sid}});return}
 if(op==='unlock'){const salt=b(e.data.salt),wk=await credentialKey(e.data.password,e.data.pattern,salt,e.data.iterations),root=await unwrap(e.data.slot,wk,`SecurePackage|V11|slot|primary|${e.data.packageId}`);if(root.length!==32)throw Error();const sid=hex(rand(16));sessions.set(sid,{root,wrapRaw:wk,salt:new Uint8Array(salt),expires:Date.now()+600000});self.postMessage({id,ok:true,result:{sessionId:sid}});return}
 if(op==='unlockRecovery'){const salt=b(e.data.salt),wk=await recoveryKey(e.data.recovery,salt,e.data.iterations),root=await unwrap(e.data.slot,wk,`SecurePackage|V11|slot|recovery|${e.data.packageId}`);if(root.length!==32)throw Error();const sid=hex(rand(16));sessions.set(sid,{root,wrapRaw:wk,salt:new Uint8Array(salt),expires:Date.now()+600000});self.postMessage({id,ok:true,result:{sessionId:sid}});return}
 if(op==='wrapCredential'){const wk=await credentialKey(e.data.password,e.data.pattern,b(e.data.salt),e.data.iterations);const slot=await wrap(b(e.data.root),wk,`SecurePackage|V11|slot|primary|${e.data.packageId}`);wk.fill(0);self.postMessage({id,ok:true,result:slot});return}
 if(op==='wrapRecovery'){const wk=await recoveryKey(e.data.recovery,b(e.data.salt),e.data.iterations);const slot=await wrap(b(e.data.root),wk,`SecurePackage|V11|slot|recovery|${e.data.packageId}`);wk.fill(0);self.postMessage({id,ok:true,result:slot});return}
 if(op==='nonce'){const s=session(e.data.sessionId),out=await nonce(s.root,e.data.context);self.postMessage({id,ok:true,result:out},[out.buffer]);return}
 if(op==='crypt'){const s=session(e.data.sessionId),out=await crypt(s,e.data.purpose,e.data.context,e.data.iv,e.data.data,e.data.aad,e.data.mode);self.postMessage({id,ok:true,result:out},[out.buffer]);return}
 if(op==='hash'){const out=await digest(e.data.data);self.postMessage({id,ok:true,result:out},[out.buffer]);return}
 if(op==='destroy'){const s=sessions.get(e.data.sessionId);if(s){s.root.fill(0);s.wrapRaw.fill(0);sessions.delete(e.data.sessionId)}self.postMessage({id,ok:true,result:true});return}
 throw Error('Unsupported operation.');
}catch(_){self.postMessage({id,ok:false,error:'Client cryptographic operation failed.'})}};
