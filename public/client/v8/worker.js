'use strict';
const sessions = new Map();
const te = new TextEncoder();
const SESSION_TTL = 10 * 60 * 1000;
const bytes = v => v instanceof Uint8Array ? v : new Uint8Array(v);
const text = v => typeof v === 'string' ? te.encode(v) : bytes(v);
const hex = b => [...bytes(b)].map(x => x.toString(16).padStart(2,'0')).join('');
const touch = s => { s.expires = Date.now() + SESSION_TTL; return s; };
function cleanup(){ const now=Date.now(); for(const [id,s] of sessions) if(s.expires<=now) sessions.delete(id); }
async function derive(password, pattern, salt, iterations){
  const material = await crypto.subtle.importKey('raw', text(password + '\u0000' + pattern), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations,hash:'SHA-256'}, material, 256);
  const master = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  const make = async label => crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:text('SecurePackage|V8|'+label)}, master, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
  const ivKey = await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:text('SecurePackage|V8|iv')}, master, {name:'HMAC',hash:'SHA-256',length:256}, false, ['sign']);
  return { manifest: await make('manifest'), name: await make('filename'), file: await make('file'), ivKey };
}
function bytesTo12(raw){return new Uint8Array(raw).slice(0,12);}
function key(s,p){ if(p==='manifest') return s.manifest; if(p==='name') return s.name; if(p==='file') return s.file; if(p==='iv') return s.ivKey; throw Error('Unsupported purpose.'); }
self.onmessage = async e => {
  const {id,op} = e.data || {}; cleanup();
  try {
    if(op==='start'){
      const keys=await derive(e.data.password,e.data.pattern,new Uint8Array(e.data.salt),e.data.iterations);
      const sid=hex(crypto.getRandomValues(new Uint8Array(16))); sessions.set(sid,touch(keys));
      self.postMessage({id,ok:true,result:{sessionId:sid}}); return;
    }
    if(op==='destroy'){sessions.delete(e.data.sessionId); self.postMessage({id,ok:true,result:true}); return;}
    const s=sessions.get(e.data.sessionId); if(!s) throw Error('Session expired.'); touch(s);
    if(op==='hash'){ const out=await crypto.subtle.digest('SHA-256',new Uint8Array(e.data.data)); self.postMessage({id,ok:true,result:out},[out]); return; }
    const k=key(s,e.data.purpose), iv=new Uint8Array(e.data.iv), aad=text(e.data.aad||'');
    if(op==='deriveIv'){ const raw=await crypto.subtle.sign('HMAC',s.ivKey,text(e.data.context)); self.postMessage({id,ok:true,result:bytesTo12(raw)},[raw]); return; }
    if(op==='crypt'){
      const out=e.data.mode==='enc'
        ? await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},k,new Uint8Array(e.data.data))
        : await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad},k,new Uint8Array(e.data.data));
      self.postMessage({id,ok:true,result:out},[out]); return;
    }
    throw Error('Unsupported operation.');
  } catch(_){ self.postMessage({id,ok:false,error:'Client cryptographic operation failed.'}); }
};
