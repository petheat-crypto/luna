const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('./planner-server');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

test('help page is reachable at /help and linked from the app', () => {
  const html=fs.readFileSync(path.join(__dirname,'docs','index.html'),'utf8');
  const page=fs.readFileSync(path.join(__dirname,'docs','help','index.html'),'utf8');
  const settings=JSON.parse(fs.readFileSync(path.join(__dirname,'vercel.json'),'utf8'));
  assert.ok(page.includes('<h1>Помощь'));
  assert.ok(page.includes('localStorage'));
  assert.ok(html.includes('href="help/"'));
  assert.ok(settings.rewrites.some(r=>r.source==='/help'&&r.destination==='/help/index.html'));
});

test('Vercel static bundle embeds the login from auth subdomain and permits only expected parent sites', () => {
  const html=fs.readFileSync(path.join(__dirname,'docs','index.html'),'utf8');
  const frame=fs.readFileSync(path.join(__dirname,'docs','planner-login.html'),'utf8');
  const settings=JSON.parse(fs.readFileSync(path.join(__dirname,'vercel.json'),'utf8'));
  assert.ok(html.includes('https://auth.owlet.bond/planner-login.html'));
  assert.ok(html.includes('https://auth.owlet.bond'));
  assert.ok(html.includes("'www.owlet.bond'"));
  assert.ok(frame.includes('https://owlet.bond'));
  assert.ok(frame.includes('https://www.owlet.bond'));
  assert.ok(settings.headers.some(h=>h.source==='/planner-login.html'&&h.headers.some(x=>x.key==='Content-Security-Policy'&&x.value.includes('frame-ancestors https://owlet.bond https://www.owlet.bond'))));
});

test('planner server serves the standalone hash-router app', async (t) => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const authFrame=await fetch(`http://127.0.0.1:${server.address().port}/login-frame`);
  assert.equal(authFrame.status,200);
  assert.equal(authFrame.headers.get('x-frame-options'),'SAMEORIGIN');
  assert.ok(authFrame.headers.get('content-security-policy').includes("frame-ancestors 'self'"));
  const frameHtml=await authFrame.text();
  assert.ok(frameHtml.includes('luna-planner-login'));
  assert.ok(frameHtml.includes('nina / 1234'));
  assert.ok(frameHtml.includes('boris / 1234'));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.ok(html.includes('Войти через Google'));
  assert.ok(html.includes('src="/login-frame"'));
  for (const route of ['#/login', '#/today', '#/week', '#/done', '#/add']) assert.ok(html.includes(route), route);
  for (const label of ['Сегодня', 'На неделе', 'Сделано', 'Добавить дело', 'nina', 'boris', 'Записаться к врачу', 'Позвонить дочери / сыну', 'Купить продукты', 'Посмотреть передачу', 'localStorage.setItem(\'luna_user\'']) assert.ok(html.includes(label), label);
});

test('Google login redirects to OAuth using the separate planner callback', async (t) => {
  const server=createServer();
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>server.close());
  const base=`http://127.0.0.1:${server.address().port}`;
  const response=await fetch(`${base}/auth/google`,{redirect:'manual'});
  assert.equal(response.status,302);
  const target=new URL(response.headers.get('location'));
  assert.equal(target.searchParams.get('response_type'),'code');
  assert.equal(target.searchParams.get('client_id'),'598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com');
  assert.equal(target.searchParams.get('redirect_uri'),'http://127.0.0.1:4174/enter');
  assert.ok(response.headers.get('set-cookie').includes('luna_planner_oauth'));
  assert.equal((await fetch(`${base}/enter?code=forged&state=invalid`,{redirect:'manual'})).status,400);
});

test('Google callback verifies the ID token and returns a local planner profile', async (t) => {
  const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),publicJwk=pair.publicKey.export({format:'jwk'});publicJwk.kid='planner-test-key';
  const server=createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const realFetch=global.fetch;t.after(()=>{global.fetch=realFetch});
  const base=`http://127.0.0.1:${server.address().port}`;
  const start=await realFetch(`${base}/auth/google`,{redirect:'manual'}),target=new URL(start.headers.get('location'));
  const nonce=target.searchParams.get('nonce'),state=target.searchParams.get('state'),cookie=start.headers.get('set-cookie').split(';')[0];
  const header=Buffer.from(JSON.stringify({alg:'RS256',kid:'planner-test-key'})).toString('base64url');
  const claims=Buffer.from(JSON.stringify({iss:'https://accounts.google.com',aud:'598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com',exp:Math.floor(Date.now()/1000)+300,nonce,email:'nina@example.com',email_verified:true,name:'Нина Google'})).toString('base64url');
  const content=`${header}.${claims}`,signer=crypto.createSign('RSA-SHA256');signer.update(content);signer.end();const idToken=`${content}.${signer.sign(pair.privateKey).toString('base64url')}`;
  global.fetch=async(input,init)=>{const address=String(input);if(address==='https://oauth2.googleapis.com/token')return new Response(JSON.stringify({id_token:idToken}),{status:200,headers:{'content-type':'application/json'}});if(address==='https://www.googleapis.com/oauth2/v3/certs')return new Response(JSON.stringify({keys:[publicJwk]}),{status:200,headers:{'content-type':'application/json'}});return realFetch(input,init)};
  const callback=await realFetch(`${base}/enter?code=mock-code&state=${state}`,{headers:{cookie},redirect:'manual'});
  assert.equal(callback.status,200);assert.match(callback.headers.get('content-type'),/text\/html/);
  const page=await callback.text();assert.ok(page.includes('google:nina@example.com'));assert.ok(page.includes('provider":"google"'));assert.ok(page.includes('window.close()'));
});

test('unknown paths are not served as the planner', async (t) => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/not-a-page`);
  assert.equal(response.status, 404);
});
