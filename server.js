const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const USERS = { ivan: { name: 'Иван', password: '1234' }, maria: { name: 'Мария', password: '1234' }, test: { name: 'Тестовый ученик', password: 'test' } };
const COURSES = [
  { id:'computer', title:'Знакомство с компьютером', desc:'Разберёмся, из чего состоит компьютер и для чего нужны его главные части.', time:'6 уроков · 2 часа', color:'#e5f0e8', lessons:['Что такое компьютер','Экран и системный блок','Включаем и выключаем компьютер','Рабочий стол','Файлы и папки','Повторяем главное'] },
  { id:'mouse', title:'Работа с мышью и клавиатурой', desc:'Научимся уверенно двигать указатель, нажимать кнопки и набирать текст.', time:'6 уроков · 2 часа', color:'#f2ead8', lessons:['Как держать мышь','Одинарный и двойной щелчок','Перетаскивание','Знакомство с клавиатурой','Печатаем короткий текст','Полезные сочетания клавиш'] },
  { id:'internet', title:'Интернет для начинающих', desc:'Откроем сайты, воспользуемся поиском и найдём нужную информацию.', time:'6 уроков · 2,5 часа', color:'#e4edf2', lessons:['Что такое интернет','Открываем браузер','Адрес сайта','Ищем информацию','Переходим по ссылкам','Закрываем лишнюю вкладку'] },
  { id:'email', title:'Электронная почта', desc:'Научимся читать письма, написать ответ и отправить сообщение близким.', time:'6 уроков · 2 часа', color:'#f1e7e7', lessons:['Что такое электронная почта','Вход в почту','Открываем письмо','Пишем новое письмо','Добавляем получателя','Отправляем и проверяем'] },
  { id:'safety', title:'Безопасность в интернете', desc:'Разберём надёжные пароли, подозрительные сообщения и безопасные привычки.', time:'5 уроков · 1,5 часа', color:'#e9e7f1', lessons:['Надёжный пароль','Не сообщаем коды','Подозрительные письма','Безопасные покупки','К кому обратиться за помощью'] },
  { id:'video', title:'Видеозвонки близким', desc:'Подготовим камеру и микрофон и научимся звонить родным.', time:'5 уроков · 1,5 часа', color:'#f5eadf', lessons:['Что нужно для звонка','Камера и микрофон','Подключаемся к звонку','Включаем и выключаем звук','Завершаем звонок'] }
];
function createServer(options={}) {
 const sessions=new Map(), oauthStates=new Map(), dataFile=options.dataFile||path.join(__dirname,'data.json'); let state={};
 if(dataFile!==':memory:'){try{state=JSON.parse(fs.readFileSync(dataFile,'utf8'))}catch{state={}}}
 const envFile=path.join(__dirname,'.env');try{for(const line of fs.readFileSync(envFile,'utf8').split(String.fromCharCode(10))){const parts=line.trim().split('=');const name=parts.shift();const value=parts.join('=').trim().replaceAll('"','').replaceAll("'",'');if(name==='GOOGLE_CLIENT_SECRET'&&value&&!process.env[name])process.env[name]=value}}catch{}
 const googleClient='598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com', googleRedirect='http://127.0.0.1:4173/enter';
 const persist=()=>{if(dataFile!==':memory:'){fs.mkdirSync(path.dirname(dataFile),{recursive:true});fs.writeFileSync(dataFile,JSON.stringify(state,null,2))}};
 const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]}));
 const send=(res,status,obj,headers={})=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers});res.end(JSON.stringify(obj))};
 const body=req=>new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>10000)reject(Error('too large'))});req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch{reject(Error('bad json'))}})});
 const server=http.createServer(async(req,res)=>{const url=new URL(req.url,'http://localhost');const cookies=parseCookies(req);let user=sessions.get(cookies.luna_session);
  if(req.method==='GET'&&url.pathname==='/auth/google'){
   const googleState=crypto.randomBytes(32).toString('hex'),nonce=crypto.randomBytes(32).toString('hex');oauthStates.set(googleState,{nonce,expires:Date.now()+600000,popup:url.searchParams.get('popup')==='1'});
   const target=new URL('https://accounts.google.com/o/oauth2/v2/auth');for(const [k,v] of Object.entries({client_id:googleClient,redirect_uri:googleRedirect,response_type:'code',scope:'openid email profile',state:googleState,nonce,prompt:'select_account'}))target.searchParams.set(k,v);
   res.writeHead(302,{location:target.toString(),'cache-control':'no-store','set-cookie':`luna_oauth_state=${googleState}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`});return res.end();
  }
  if(req.method==='GET'&&url.pathname==='/enter'){
   const cookieState=cookies.luna_oauth_state,queryState=url.searchParams.get('state'),saved=oauthStates.get(queryState);oauthStates.delete(queryState);
   if(!cookieState||!queryState||cookieState!==queryState||!saved||saved.expires<Date.now())return send(res,400,{error:'Проверка входа Google не пройдена. Начните вход заново.'});
   if(url.searchParams.has('error'))return send(res,400,{error:'Вход через Google отменён.'});
   if(!process.env.GOOGLE_CLIENT_SECRET)return send(res,503,{error:'Google-вход пока не настроен: укажите GOOGLE_CLIENT_SECRET в файле .env'});
   try{
    const form=new URLSearchParams({code:url.searchParams.get('code')||'',client_id:googleClient,client_secret:process.env.GOOGLE_CLIENT_SECRET,redirect_uri:googleRedirect,grant_type:'authorization_code'});
    const tokenReply=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form,signal:AbortSignal.timeout(10000)});if(!tokenReply.ok)throw Error('Google token exchange failed');
    const tokenData=await tokenReply.json(),parts=(tokenData.id_token||'').split('.');if(parts.length!==3)throw Error('Missing ID token');
    const header=JSON.parse(Buffer.from(parts[0],'base64url').toString()),claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());if(header.alg!=='RS256'||!header.kid)throw Error('Invalid token header');
    const certReply=await fetch('https://www.googleapis.com/oauth2/v3/certs',{signal:AbortSignal.timeout(10000)});if(!certReply.ok)throw Error('Google signing keys unavailable');const certs=await certReply.json(),jwk=certs.keys.find(k=>k.kid===header.kid);if(!jwk)throw Error('Unknown signing key');
    const verify=crypto.createVerify('RSA-SHA256');verify.update(`${parts[0]}.${parts[1]}`);verify.end();if(!verify.verify(crypto.createPublicKey({key:jwk,format:'jwk'}),Buffer.from(parts[2],'base64url')))throw Error('Invalid token signature');
    const now=Math.floor(Date.now()/1000);if(!['accounts.google.com','https://accounts.google.com'].includes(claims.iss)||claims.aud!==googleClient||claims.exp<=now||claims.nonce!==saved.nonce||claims.email_verified!==true||!claims.email)throw Error('Invalid ID token claims');
    const sid=crypto.randomBytes(32).toString('hex'),googleUser={login:`google:${claims.email.toLowerCase()}`,name:claims.name||claims.email};sessions.set(sid,googleUser);
    const completion=saved.popup?'<script>if(window.opener)window.opener.postMessage("luna-google-auth-complete",window.location.origin);window.close()</script>':'<script>window.location.replace("/dashboard")</script>';res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','set-cookie':[ `luna_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`, 'luna_oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' ]});return res.end(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Вход выполнен</title><body><p>Вход выполнен.</p>${completion}</body></html>`);
   }catch(error){console.error('Google OAuth callback failed:',error.message);return send(res,401,{error:'Не удалось подтвердить вход Google. Попробуйте ещё раз.'})}
  }
  if(req.method==='GET'&&url.pathname==='/api/me')return user?send(res,200,{user}):send(res,401,{error:'Войдите в портал'});
  if(req.method==='POST'&&url.pathname==='/api/login'){try{const b=await body(req),u=USERS[String(b.login||'').toLowerCase()];if(!u||b.password!==u.password)return send(res,401,{error:'Проверьте логин и пароль'});const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{login:String(b.login).toLowerCase(),name:u.name});return send(res,200,{user:sessions.get(sid)},{'set-cookie':`luna_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`})}catch{return send(res,400,{error:'Не удалось обработать запрос'})}}
  if(req.method==='POST'&&url.pathname==='/api/logout'){sessions.delete(cookies.luna_session);return send(res,200,{ok:true},{'set-cookie':'luna_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'})}
  if(req.method==='POST'&&url.pathname==='/api/consent'){try{const b=await body(req);if(!['necessary','all','custom'].includes(b.choice))return send(res,400,{error:'Неверный выбор'});return send(res,200,{ok:true},{'set-cookie':`luna_consent=${b.choice}; SameSite=Lax; Path=/; Max-Age=31536000`})}catch{return send(res,400,{error:'Неверный запрос'})}}
  if(url.pathname.startsWith('/api/')){if(!user)return send(res,401,{error:'Войдите в портал'});const key=user.login;state[key] ||= {enrollments:[],progress:{},notifications:[]};const data=state[key];
   if(req.method==='GET'&&url.pathname==='/api/state')return send(res,200,{user,courses:COURSES,enrollments:data.enrollments,progress:data.progress,notifications:data.notifications});
   if(req.method==='POST'&&url.pathname==='/api/enroll'){const b=await body(req);if(!COURSES.some(c=>c.id===b.id))return send(res,404,{error:'Курс не найден'});if(!data.enrollments.includes(b.id))data.enrollments.push(b.id);persist();return send(res,200,{ok:true})}
   if(req.method==='POST'&&url.pathname==='/api/lesson'){const b=await body(req),c=COURSES.find(x=>x.id===b.id),i=Number(b.lesson);if(!c||!data.enrollments.includes(b.id)||!Number.isInteger(i)||i<0||i>=c.lessons.length)return send(res,400,{error:'Урок недоступен'});data.progress[b.id]=[...new Set([...(data.progress[b.id]||[]),i])].sort((a,b)=>a-b);persist();return send(res,200,{ok:true,progress:data.progress[b.id]})}
   if(req.method==='POST'&&url.pathname==='/api/notification/read'){const b=await body(req);if(!data.notifications.includes(b.id))data.notifications.push(b.id);persist();return send(res,200,{ok:true})}return send(res,404,{error:'Не найдено'})}
  if(req.method==='GET'&&['/','/index.html','/login','/dashboard','/catalog','/notifications','/help'].includes(url.pathname)||req.method==='GET'&&/^\/course\/[a-z]+$/.test(url.pathname)){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res)}
  send(res,404,{error:'Не найдено'});
 });return server;
}
if(require.main===module){const port=Number(process.env.PORT)||4173;createServer().listen(port,'127.0.0.1',()=>console.log(`Луна Академия запущена: http://127.0.0.1:${port}`))}
module.exports={createServer,COURSES};
