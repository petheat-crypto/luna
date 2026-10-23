const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('./server');
const crypto = require('node:crypto');

test('пользователь может войти, получить HttpOnly session cookie и увидеть дашборд', async (t) => {
  const server = createServer({ port: 0, dataFile: ':memory:' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const login = await fetch(`${base}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: 'ivan', password: '1234' }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  const response = await fetch(`${base}/api/me`, { headers: { cookie: cookie.split(';')[0] } });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).user.name, 'Иван');
});

test('без авторизации защищённые данные недоступны; согласие cookies сохраняется', async (t) => {
  const server = createServer({ port: 0, dataFile: ':memory:' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/api/state`)).status, 401);
  const response = await fetch(`${base}/api/consent`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ choice: 'necessary' }) });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('set-cookie'), /luna_consent=necessary/);
});

test('Google login starts OAuth authorization with a CSRF state and callback rejects a forged state', async (t) => {
  const server = createServer({ dataFile: ':memory:' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const start = await fetch(`${base}/auth/google`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const destination = new URL(start.headers.get('location'));
  assert.equal(destination.searchParams.get('response_type'), 'code');
  assert.equal(destination.searchParams.get('client_id'), '598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com');
  assert.ok(destination.searchParams.get('state'));
  const callback = await fetch(`${base}/enter?code=not-a-code&state=forged`, { redirect: 'manual' });
  assert.equal(callback.status, 400);
});

test('dashboard, catalog, notifications, help and course are separate documents', async (t) => {
  const server = createServer({ dataFile: ':memory:' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const route of ['/dashboard', '/catalog', '/notifications', '/help', '/course/computer']) {
    const response = await fetch(base + route);
    assert.equal(response.status, 200, route);
    assert.match(response.headers.get('content-type'), /text\/html/);
  }
});

test('успешный OAuth в попапе закрывает его и устанавливает общую сессию', async (t) => {
  const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048}), publicJwk=pair.publicKey.export({format:'jwk'});publicJwk.kid='test-key';
  const server = createServer({ dataFile: ':memory:' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const realFetch=global.fetch;
  t.after(() => { global.fetch=realFetch });
  const base = `http://127.0.0.1:${server.address().port}`;
  const start=await realFetch(`${base}/auth/google?popup=1`,{redirect:'manual'}),dest=new URL(start.headers.get('location'));
  const state=dest.searchParams.get('state'),nonce=dest.searchParams.get('nonce'),stateCookie=start.headers.get('set-cookie').split(';')[0];
  const head=Buffer.from(JSON.stringify({alg:'RS256',kid:'test-key'})).toString('base64url');
  const payload=Buffer.from(JSON.stringify({iss:'https://accounts.google.com',aud:'598819156685-pdli5q93l8rn6ilfqbvpecbccsimb8o9.apps.googleusercontent.com',exp:Math.floor(Date.now()/1000)+300,nonce,email:'student@example.com',email_verified:true,name:'Student'})).toString('base64url');
  const signed=`${head}.${payload}`,signer=crypto.createSign('RSA-SHA256');signer.update(signed);signer.end();const idToken=`${signed}.${signer.sign(pair.privateKey).toString('base64url')}`;
  global.fetch=async(input,init)=>{const target=String(input);if(target==='https://oauth2.googleapis.com/token')return new Response(JSON.stringify({id_token:idToken}),{status:200,headers:{'content-type':'application/json'}});if(target==='https://www.googleapis.com/oauth2/v3/certs')return new Response(JSON.stringify({keys:[publicJwk]}),{status:200,headers:{'content-type':'application/json'}});return realFetch(input,init)};
  const callback=await realFetch(`${base}/enter?code=fake-code&state=${state}`,{headers:{cookie:stateCookie},redirect:'manual'});
  assert.equal(callback.status,200);
  const html=await callback.text();assert.ok(html.includes('window.close()'));assert.ok(!html.includes('location.replace("/dashboard")'));
  const session=callback.headers.getSetCookie().find(value=>value.startsWith('luna_session=')).split(';')[0];
  const me=await realFetch(`${base}/api/me`,{headers:{cookie:session}});assert.equal((await me.json()).user.name,'Student');
});

