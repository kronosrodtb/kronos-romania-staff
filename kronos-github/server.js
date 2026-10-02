const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'store.json');
const USE_DB = !!process.env.DATABASE_URL;
let pool = null;

if (USE_DB) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
  });
}

const EMPTY_DATA = { events: {}, rules: {}, customEvents: [], customRules: [] };
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!USE_DB && !fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ owner: null, data: EMPTY_DATA }, null, 2));

function readFileStore() {
  try {
    const s = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return normalizeStore(s);
  } catch {
    return { owner: null, data: structuredClone(EMPTY_DATA) };
  }
}
function normalizeData(d) {
  d = d || {};
  return {
    events: d.events || {},
    rules: d.rules || {},
    customEvents: Array.isArray(d.customEvents) ? d.customEvents : [],
    customRules: Array.isArray(d.customRules) ? d.customRules : []
  };
}
function normalizeStore(s) { return { owner: s?.owner || null, data: normalizeData(s?.data) }; }
function writeFileStore(s) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(normalizeStore(s), null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

async function initDb() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS kronos_owner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS kronos_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`INSERT INTO kronos_state (id, data) VALUES (1, $1::jsonb) ON CONFLICT (id) DO NOTHING`, [JSON.stringify(EMPTY_DATA)]);
}
async function getOwner() {
  if (!pool) return readFileStore().owner;
  const r = await pool.query('SELECT username, salt, password_hash AS hash, created_at FROM kronos_owner WHERE id=1');
  return r.rows[0] || null;
}
async function getData() {
  if (!pool) return readFileStore().data;
  const r = await pool.query('SELECT data FROM kronos_state WHERE id=1');
  return normalizeData(r.rows[0]?.data);
}
async function saveData(data) {
  data = normalizeData(data);
  if (!pool) {
    const s = readFileStore(); s.data = data; writeFileStore(s);
    return new Date().toISOString();
  }
  const r = await pool.query('UPDATE kronos_state SET data=$1::jsonb, updated_at=NOW() WHERE id=1 RETURNING updated_at', [JSON.stringify(data)]);
  return r.rows[0].updated_at;
}
async function createOwner(username, salt, hash) {
  if (!pool) { const s=readFileStore(); s.owner={username,salt,hash,createdAt:new Date().toISOString()}; writeFileStore(s); return; }
  await pool.query('INSERT INTO kronos_owner (id, username, salt, password_hash) VALUES (1,$1,$2,$3)', [username,salt,hash]);
}

function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function makePassword(password) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPassword(password, salt) }; }
function verifyPassword(password, owner) {
  if (!owner) return false;
  const h = hashPassword(password, owner.salt);
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(owner.hash, 'hex'));
}

const sessions = new Map();
function newSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expires: Date.now() + 8 * 60 * 60 * 1000 });
  return token;
}
function getSession(req) {
  const m = (req.headers.cookie || '').match(/(?:^|; )kronos_session=([^;]+)/);
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s || s.expires < Date.now()) { if (s) sessions.delete(m[1]); return null; }
  return s;
}
function cookie(token, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `kronos_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`;
}
function json(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', ...headers });
  res.end(body);
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let b='';
    req.on('data', c => { b += c; if (b.length > 2e6) { reject(new Error('Payload prea mare.')); req.destroy(); } });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch(e) { reject(e); } });
    req.on('error', reject);
  });
}
function safePath(urlPath) {
  const clean = decodeURIComponent(urlPath.split('?')[0]);
  const p = path.normalize(path.join(ROOT, clean === '/' ? 'index.html' : clean));
  return p.startsWith(ROOT) ? p : null;
}
function contentType(p) {
  const e=path.extname(p).toLowerCase();
  return {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml'}[e] || 'application/octet-stream';
}

const server = http.createServer(async (req,res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      if (req.method === 'GET' && url.pathname === '/api/status') {
        const owner = await getOwner(); const session = getSession(req);
        return json(res,200,{ setupRequired:!owner, authenticated:!!session, username:session?.username||null, database:USE_DB });
      }
      if (req.method === 'POST' && url.pathname === '/api/setup') {
        const owner = await getOwner(); if (owner) return json(res,409,{error:'Contul Owner există deja.'});
        const b=await parseBody(req); const username=String(b.username||'').trim(); const password=String(b.password||'');
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return json(res,400,{error:'Username invalid.'});
        if (password.length < 10) return json(res,400,{error:'Parola trebuie să aibă cel puțin 10 caractere.'});
        const p=makePassword(password); await createOwner(username,p.salt,p.hash);
        const token=newSession(username); return json(res,200,{ok:true},{'Set-Cookie':cookie(token,28800)});
      }
      if (req.method === 'POST' && url.pathname === '/api/login') {
        const owner=await getOwner(); if(!owner) return json(res,428,{error:'Contul Owner nu este configurat.'});
        const b=await parseBody(req); if(String(b.username||'')!==owner.username || !verifyPassword(String(b.password||''),owner)) return json(res,401,{error:'Date de autentificare incorecte.'});
        const token=newSession(owner.username); return json(res,200,{ok:true},{'Set-Cookie':cookie(token,28800)});
      }
      if (req.method === 'POST' && url.pathname === '/api/logout') {
        const m=(req.headers.cookie||'').match(/(?:^|; )kronos_session=([^;]+)/); if(m) sessions.delete(m[1]);
        return json(res,200,{ok:true},{'Set-Cookie':cookie('',0)});
      }
      if (req.method === 'GET' && url.pathname === '/api/public-data') {
        const d=await getData(); return json(res,200,d);
      }
      if (req.method === 'GET' && url.pathname === '/api/data') {
        if(!getSession(req)) return json(res,401,{error:'Neautorizat.'});
        return json(res,200,await getData());
      }
      if (req.method === 'POST' && url.pathname === '/api/data') {
        if(!getSession(req)) return json(res,401,{error:'Neautorizat.'});
        const b=await parseBody(req); if(!b || typeof b!=='object' || !b.events || !b.rules || !Array.isArray(b.customEvents||[]) || !Array.isArray(b.customRules||[])) return json(res,400,{error:'Date invalide.'});
        const savedAt=await saveData(b); return json(res,200,{ok:true,savedAt});
      }
      if (req.method === 'POST' && url.pathname === '/api/reset') {
        if(!getSession(req)) return json(res,401,{error:'Neautorizat.'});
        await saveData(EMPTY_DATA); return json(res,200,{ok:true});
      }
      return json(res,404,{error:'Endpoint inexistent.'});
    }
    const p=safePath(url.pathname); if(!p || !fs.existsSync(p) || !fs.statSync(p).isFile()) return json(res,404,{error:'Not found'});
    res.writeHead(200,{'Content-Type':contentType(p),'Cache-Control':p.endsWith('.html')?'no-cache':'public, max-age=3600'}); fs.createReadStream(p).pipe(res);
  } catch(e) { console.error(e); json(res,500,{error:'Eroare server.'}); }
});

(async()=>{
  try { await initDb(); server.listen(PORT,HOST,()=>console.log(`Kronos server: http://${HOST}:${PORT} | storage: ${USE_DB?'PostgreSQL':'local file'}`)); }
  catch(e) { console.error('Database initialization failed:',e); process.exit(1); }
})();
