// Login gateway: argon2id passwords, HS256 JWT cookie, then proxies each user to their own Nod.
import assert from 'node:assert';
import { argon2, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { promisify } from 'node:util';

const selftest = process.argv.includes('--selftest');
const dir = process.env.USERS_DIR ?? 'users';
const origin = new URL(process.env.GATEWAY_URL ?? 'http://localhost:4300').origin;
const COOKIE = 'nod_session';
const TTL = 12 * 3600;
const PARAMS = { memory: 65536, passes: 3, parallelism: 1, tagLength: 32 };
const HEADER = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');

const same = (a, b) => {
  const [x, y] = [Buffer.from(a), Buffer.from(b)];
  return x.length === y.length && timingSafeEqual(x, y);
};

const derive = promisify(argon2);
const phc = (bytes) => bytes.toString('base64').replace(/=+$/, '');
async function hash(password, nonce = randomBytes(16), p = PARAMS) {
  const tag = await derive('argon2id', { message: password, nonce, ...p });
  return `$argon2id$v=19$m=${p.memory},t=${p.passes},p=${p.parallelism}$${phc(nonce)}$${phc(tag)}`;
}
async function verify(password, stored) {
  const [, , , params, salt, tag] = stored.split('$');
  const [memory, passes, parallelism] = params.split(',').map((part) => Number(part.slice(2)));
  const tagLength = Buffer.from(tag, 'base64').length;
  const actual = await hash(password, Buffer.from(salt, 'base64'), { memory, passes, parallelism, tagLength });
  return same(actual, stored);
}
// ponytail: one argon2 at a time (64 MiB each), unbounded queue; add per-IP limits at the reverse proxy if exposed publicly
let queue = Promise.resolve();
const serial = (work) => (queue = queue.then(work, work));

function loadSecret() {
  const path = `${dir}/jwt-secret`;
  try {
    writeFileSync(path, randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  return readFileSync(path, 'utf8');
}
const secret = selftest ? randomBytes(32) : loadSecret();
const mac = (body) => createHmac('sha256', secret).update(body).digest('base64url');
const sign = (payload) => {
  const body = `${HEADER}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return `${body}.${mac(body)}`;
};
// The header is compared verbatim, so only HS256 tokens this gateway issued are accepted.
function claims(token = '') {
  const [header, payload, signature, ...rest] = token.split('.');
  if (rest.length || header !== HEADER || !signature || !same(signature, mac(`${header}.${payload}`))) return;
  const parsed = JSON.parse(Buffer.from(payload, 'base64url'));
  return parsed.exp > Date.now() / 1000 ? parsed : undefined;
}

if (selftest) {
  const stored = await hash('correct horse battery');
  assert(stored.startsWith('$argon2id$v=19$m=65536,t=3,p=1$'));
  assert(await verify('correct horse battery', stored));
  assert(!(await verify('wrong horse battery', stored)));
  const exp = Math.floor(Date.now() / 1000) + 60;
  const token = sign({ sub: 'alice', exp });
  assert.equal(claims(token).sub, 'alice');
  assert.equal(claims(sign({ sub: 'alice', exp: 1 })), undefined);
  assert.equal(claims(`${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`), undefined);
  const forged = Buffer.from(JSON.stringify({ sub: 'bob', exp })).toString('base64url');
  assert.equal(claims(`${HEADER}.${forged}.${token.split('.')[2]}`), undefined);
  assert.equal(claims(`${Buffer.from('{"alg":"none"}').toString('base64url')}.${forged}.`), undefined);
  console.log('selftest ok');
  process.exit(0);
}

const accountsPath = `${dir}/accounts.json`;
let accounts = new Map();
try {
  accounts = new Map(Object.entries(JSON.parse(readFileSync(accountsPath, 'utf8'))));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
function saveAccounts() {
  writeFileSync(`${accountsPath}.tmp`, JSON.stringify(Object.fromEntries(accounts), null, 2), { mode: 0o600 });
  renameSync(`${accountsPath}.tmp`, accountsPath);
}

function instance(name) {
  if (!/^[a-z0-9]{1,32}$/.test(name)) return;
  let text;
  try {
    text = readFileSync(`${dir}/${name}.env`, 'utf8');
  } catch {
    return;
  }
  const value = (key) => text.match(new RegExp(`^${key}=(.*)$`, 'm'))?.[1];
  const [port, token] = [Number(value('PORT')), value('NOD_AUTH_TOKEN')];
  return port && token ? { port, token } : undefined;
}

// ponytail: tokens are not revocable before expiry except by deleting the account and restarting
function session(request) {
  const token = request.headers.cookie
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
  const user = claims(token)?.sub;
  return accounts.has(user) ? instance(user) : bearer(request);
}

// The Nod desktop app sends its server token on every request; it skips the password, so treat that token as a secret.
function bearer(request) {
  const token = /^Bearer ([A-Za-z0-9_-]{43,})$/i.exec(request.headers.authorization ?? '')?.[1];
  if (!token) return;
  return readdirSync(dir)
    .filter((file) => file.endsWith('.env'))
    .map((file) => instance(file.slice(0, -4)))
    .find((target) => target && same(token, target.token));
}

const DUMMY = await hash(randomBytes(16).toString('hex'));
const fails = new Map();
const LOCK_AFTER = 5;
const LOCK_MS = 15 * 60_000;

const STYLE = `
:root{color-scheme:light dark;--bg:#f6f5f3;--card:#fff;--text:#191919;--muted:#6b6b6b;--line:#dcdad6;--accent:#ff91ac;--error:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#191919;--card:#232323;--text:#f2f1ef;--muted:#a3a3a3;--line:#3a3a3a;--error:#ffb4ab}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}
main{width:100%;max-width:380px;padding:32px;background:var(--card);border:1px solid var(--line);border-radius:16px}
h1{margin:0 0 4px;font-size:28px}
h2{margin:0 0 16px;font-size:16px;font-weight:400;color:var(--muted)}
label{display:block;margin-bottom:16px;font-size:14px;font-weight:600}
input{display:block;width:100%;margin-top:6px;padding:10px 12px;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:8px}
input:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{width:100%;padding:11px;font:inherit;font-weight:600;color:#191919;background:var(--accent);border:0;border-radius:8px;cursor:pointer}
[role=alert]{margin:0 0 16px;padding:10px 12px;font-size:14px;color:var(--error);border:1px solid currentColor;border-radius:8px}
[role=alert]:empty{display:none}
details{margin-top:24px;padding-top:20px;border-top:1px solid var(--line)}
summary{cursor:pointer;font-size:14px;font-weight:600}
details form{margin-top:16px}
`;
const CSP = `default-src 'none'; style-src 'sha256-${createHash('sha256').update(STYLE).digest('base64')}'; form-action 'self'; frame-ancestors 'none'`;
// Where to land after signing in; the strict charset blocks open redirects and makes it safe to embed in the form.
const safe = (next) => (/^\/(?!\/)[\w\-./?=&%]*$/.test(next ?? '') ? next : '/');
const page = (response, status, message = '', signup = false, next = '/') =>
  response
    .writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      // Not no-referrer: that makes browsers send "Origin: null" on the form POST, which the origin check rejects
      'Referrer-Policy': 'same-origin',
      'Cache-Control': 'no-store',
    })
    .end(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nod sign in</title><style>${STYLE}</style>
<main><h1>Nod</h1><h2>Sign in to your assistant</h2><p role="alert">${message}</p>
<form method="post" action="/_auth/login"><input type="hidden" name="next" value="${safe(next)}">
<label>Username <input name="username" autocomplete="username" autocapitalize="none" required${signup ? '' : ' autofocus'}></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button>Sign in</button></form>
<details${signup ? ' open' : ''}><summary>First time? Create your password</summary>
<form method="post" action="/_auth/signup"><input type="hidden" name="next" value="${safe(next)}">
<label>Username <input name="username" autocomplete="username" autocapitalize="none" required></label>
<label>Invite code <input name="invite" autocomplete="off" required></label>
<label>New password (12 or more characters) <input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label>
<button>Create account</button></form></details></main></html>`);

const cookie = (value, maxAge) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${origin.startsWith('https:') ? '; Secure' : ''}`;
const enter = (response, user, next) =>
  response
    .writeHead(303, {
      Location: safe(next),
      'Set-Cookie': cookie(sign({ sub: user, exp: Math.floor(Date.now() / 1000) + TTL }), TTL),
    })
    .end();

async function form(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 4096) throw new Error('Form too large.');
  }
  return Object.fromEntries(new URLSearchParams(body));
}

// Browsers state where a form came from in Sec-Fetch-Site; Origin can legitimately be "null" (privacy settings, referrer policy), so it is only the fallback.
function sameSite(request) {
  const site = request.headers['sec-fetch-site'];
  if (site) return site === 'same-origin' || site === 'none';
  if (!request.headers.origin) return true;
  try {
    return new URL(request.headers.origin).host === request.headers.host;
  } catch {
    return false;
  }
}

async function auth(request, response, path) {
  if (request.method === 'GET' && path === '/_auth/login') return page(response, 200, '', false, new URLSearchParams(request.url.split('?')[1]).get('next'));
  if (request.method !== 'POST') return response.writeHead(404).end();
  if (!sameSite(request)) {
    console.warn('Refused cross-site form post', { origin: request.headers.origin, site: request.headers['sec-fetch-site'], host: request.headers.host });
    return response.writeHead(403, { 'Content-Type': 'text/plain' }).end('Cross-site form posts are not permitted. Reload the sign-in page and try again.');
  }
  if (path === '/_auth/logout') return response.writeHead(303, { Location: '/_auth/login', 'Set-Cookie': cookie('', 0) }).end();
  const fields = await form(request);
  // Pasted tokens pick up stray spaces and phones capitalise the first letter; neither should fail a sign-in.
  const username = (fields.username ?? '').trim().toLowerCase();
  const invite = (fields.invite ?? '').trim();
  const { password = '', next } = fields;
  const sized = password.length >= 12 && password.length <= 128;
  if (path === '/_auth/signup') {
    // The invite code is that user's NOD_AUTH_TOKEN, handed over by the admin; only provisioned users can sign up.
    const target = instance(username);
    const invited = !!target && same(invite, target.token);
    // Specific reasons are shown only to someone holding the right invite code.
    if (!invited) return page(response, 400, 'That username and invite code do not match. Check both and try again.', true, next);
    if (accounts.has(username))
      return page(response, 400, 'This account already has a password. Sign in above, or ask your admin to reset it.', false, next);
    if (!sized) return page(response, 400, 'Use a password of 12 to 128 characters.', true, next);
    const stored = await serial(() => hash(password));
    if (accounts.has(username)) return page(response, 400, 'This account already has a password. Sign in above.', false, next);
    accounts.set(username, stored);
    saveAccounts();
    return enter(response, username, next);
  }
  if (path === '/_auth/login') {
    const failed = fails.get(username);
    if (failed?.count >= LOCK_AFTER && Date.now() < failed.until)
      return page(response, 429, 'Too many attempts. Try again in 15 minutes.', false, next);
    const stored = accounts.get(username);
    // Unknown users still cost one argon2 run, so timing does not reveal which usernames exist.
    const ok = password.length <= 128 && (await serial(() => verify(password, stored ?? DUMMY))) && !!stored;
    if (ok) {
      fails.delete(username);
      return enter(response, username, next);
    }
    if (stored) {
      const count = failed && Date.now() < failed.until ? failed.count + 1 : 1;
      fails.set(username, { count, until: Date.now() + LOCK_MS });
    }
    return page(response, 401, 'Wrong username or password.', false, next);
  }
  response.writeHead(404).end();
}

const forwarded = (request, target) => ({ ...request.headers, authorization: `Bearer ${target.token}` });

// ponytail: routing is by login cookie, so cookieless inbound webhooks (Telegram webhook mode, WhatsApp Cloud API) are not routed; give those users their own hostname if needed
const server = http.createServer(async (request, response) => {
  try {
    const path = request.url.split('?')[0];
    if (path.startsWith('/_auth/')) return await auth(request, response, path);
    const target = session(request);
    if (!target)
      return request.method === 'GET' && request.headers['sec-fetch-dest'] === 'document'
        ? response.writeHead(303, { Location: `/_auth/login?next=${encodeURIComponent(request.url)}` }).end()
        : response.writeHead(401).end('Sign in first.');
    const upstream = http.request(
      { host: '127.0.0.1', port: target.port, method: request.method, path: request.url, headers: forwarded(request, target) },
      (result) => {
        response.writeHead(result.statusCode, result.headers);
        result.pipe(response);
      },
    );
    upstream.on('error', () => (response.headersSent ? response.destroy() : response.writeHead(502).end('Nod is not running.')));
    response.on('close', () => upstream.destroy());
    request.pipe(upstream);
  } catch {
    response.headersSent ? response.destroy() : response.writeHead(400).end();
  }
});

server.on('upgrade', (request, socket, head) => {
  const target = session(request);
  if (!target) return socket.end('HTTP/1.1 401 Unauthorized\r\n\r\n');
  const upstream = net.connect(target.port, '127.0.0.1', () => {
    const lines = Object.entries(forwarded(request, target)).map(([name, value]) => `${name}: ${value}\r\n`);
    upstream.write(`${request.method} ${request.url} HTTP/1.1\r\n${lines.join('')}\r\n`);
    upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
});

server.listen(Number(process.env.GATEWAY_PORT ?? 4300), '127.0.0.1');
