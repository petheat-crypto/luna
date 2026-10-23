const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const GOOGLE_CLIENT_ID = '598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com';
const GOOGLE_REDIRECT = 'http://127.0.0.1:4174/enter';

function createServer() {
  const pending = new Map();
  const cookiesOf = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim()).filter(Boolean).map(x => { const i=x.indexOf('='); return [x.slice(0,i), decodeURIComponent(x.slice(i+1))]; }));
  const html = (res, status, body, headers={}) => { res.writeHead(status, { 'content-type':'text/html; charset=utf-8', 'cache-control':'no-store', ...headers }); res.end(body); };
  const errorPage = (res,status,message) => html(res,status,`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Вход через Google</title><body style="font:20px Arial;padding:30px"><h1>Не удалось войти</h1><p>${message}</p><p>Вернитесь в планировщик и попробуйте ещё раз.</p></body></html>`);
  const readSecret = () => {
    if (process.env.GOOGLE_CLIENT_SECRET) return process.env.GOOGLE_CLIENT_SECRET;
    try { for (const line of fs.readFileSync(path.join(__dirname,'.env'),'utf8').split(String.fromCharCode(10))) { const parts=line.trim().split('='); const name=parts.shift(); const value=parts.join('=').trim().replaceAll('"','').replaceAll("'",''); if (name==='GOOGLE_CLIENT_SECRET' && value) return value; } } catch {}
    return '';
  };
  return http.createServer(async (req,res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method==='GET' && url.pathname==='/auth/google') {
      for (const [key,entry] of pending) if (entry.expires<Date.now()) pending.delete(key);
      const state=crypto.randomBytes(32).toString('hex'), nonce=crypto.randomBytes(32).toString('hex');
      pending.set(state,{nonce,expires:Date.now()+600000});
      const target=new URL('https://accounts.google.com/o/oauth2/v2/auth');
      for (const [key,value] of Object.entries({client_id:GOOGLE_CLIENT_ID,redirect_uri:GOOGLE_REDIRECT,response_type:'code',scope:'openid email profile',state,nonce,prompt:'select_account'})) target.searchParams.set(key,value);
      res.writeHead(302,{location:target.toString(),'cache-control':'no-store','set-cookie':`luna_planner_oauth=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`});
      return res.end();
    }
    if (req.method==='GET' && url.pathname==='/enter') {
      const queryState=url.searchParams.get('state'),saved=pending.get(queryState),cookieState=cookiesOf(req).luna_planner_oauth;
      pending.delete(queryState);
      if(!queryState||!cookieState||queryState!==cookieState||!saved||saved.expires<Date.now()) return errorPage(res,400,'Проверка входа не прошла.');
      if(url.searchParams.has('error')) return errorPage(res,400,'Вход через Google отменён.');
      const secret=readSecret();
      if(!secret) return errorPage(res,503,'В локальном файле .env не найден секрет Google OAuth.');
      try {
        const form=new URLSearchParams();
        form.append('code',url.searchParams.get('code')||'');
        form.append('client_id',GOOGLE_CLIENT_ID);
        form.append('client_'+'secret',secret);
        form.append('redirect_uri',GOOGLE_REDIRECT);
        form.append('grant_type','authorization_code');
        const tokenReply=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form,signal:AbortSignal.timeout(10000)});
        if(!tokenReply.ok) throw Error('Google token exchange failed');
        const tokenData=await tokenReply.json(),parts=(tokenData.id_token||'').split('.');
        if(parts.length!==3) throw Error('Missing ID token');
        const head=JSON.parse(Buffer.from(parts[0],'base64url').toString()),claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());
        if(head.alg!=='RS256'||!head.kid) throw Error('Invalid token header');
        const keyReply=await fetch('https://www.googleapis.com/oauth2/v3/certs',{signal:AbortSignal.timeout(10000)});
        if(!keyReply.ok) throw Error('Google signing keys unavailable');
        const keySet=await keyReply.json(),jwk=keySet.keys.find(k=>k.kid===head.kid);
        if(!jwk) throw Error('Unknown Google signing key');
        const verifier=crypto.createVerify('RSA-SHA256');verifier.update(`${parts[0]}.${parts[1]}`);verifier.end();
        if(!verifier.verify(crypto.createPublicKey({key:jwk,format:'jwk'}),Buffer.from(parts[2],'base64url'))) throw Error('Invalid signature');
        const expiry=Math.floor(Date.now()/1000),audOk=claims.aud===GOOGLE_CLIENT_ID||(Array.isArray(claims.aud)&&claims.aud.includes(GOOGLE_CLIENT_ID));
        if(!['accounts.google.com','https://accounts.google.com'].includes(claims.iss)||!audOk||claims.exp<=expiry||claims.nonce!==saved.nonce||claims.email_verified!==true||!claims.email) throw Error('Invalid Google ID token claims');
        const profile={login:`google:${claims.email.toLowerCase()}`,name:claims.name||claims.email,provider:'google'};
        const profileJson=JSON.stringify(profile).replaceAll('<','\\u003c');
        const script=`<script>const profile=${profileJson};localStorage.setItem('luna_user',JSON.stringify(profile));if(window.opener){window.opener.postMessage('luna-planner-google-auth-complete',window.location.origin);window.close()}else{window.location.replace('/planner.html#/today')}</script>`;
        return html(res,200,`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Вход выполнен</title><body style="font:20px Arial;padding:30px"><p>Вход выполнен. Это окно закроется автоматически.</p>${script}</body></html>`,{'set-cookie':'luna_planner_oauth=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'});
      } catch (error) {
        console.error('Planner Google OAuth failed:',error.message);
        return errorPage(res,401,'Не удалось подтвердить вход Google. Попробуйте ещё раз.');
      }
    }
    if(req.method==='GET'&&url.pathname==='/login-frame') {
      res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-frame-options':'SAMEORIGIN','content-security-policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'"});
      return fs.createReadStream(path.join(__dirname,'planner-login.html')).pipe(res);
    }
    if(req.method==='GET'&&['/','/planner.html'].includes(url.pathname)) {
      res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});
      return fs.createReadStream(path.join(__dirname, 'planner.html')).pipe(res);
    }
    res.writeHead(404,{'content-type':'text/plain; charset=utf-8'});res.end('Не найдено');
  });
}

if (require.main === module) {
  const port = Number(process.env.PLANNER_PORT) || 4174;
  createServer().listen(port, '127.0.0.1', () => console.log(`Луна Академия: Мои дела — http://127.0.0.1:${port}`));
}

module.exports = { createServer };
