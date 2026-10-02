import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const EMPTY_DATA = { events: {}, rules: {}, customEvents: [], customRules: [] };
const SESSION_TTL = 8 * 60 * 60; // 8 hours

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function normalizeData(d) {
  d = d || {};
  return {
    events: d.events || {},
    rules: d.rules || {},
    customEvents: Array.isArray(d.customEvents) ? d.customEvents : [],
    customRules: Array.isArray(d.customRules) ? d.customRules : [],
  };
}

function cookie(token, maxAge) {
  const secure = maxAge > 0 ? '; Secure' : '';
  return `kronos_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`;
}

function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function createSession(username, secret) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const payload = base64url(JSON.stringify({ u: username, exp }));
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function getSession(request, secret) {
  if (!secret) return null;
  const token = getCookie(request, 'kronos_session');
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = createHmac('sha256', secret).update(payload).digest();
  const received = Buffer.from(signature, 'base64url');
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.u || !data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    return { username: data.u, expires: data.exp };
  } catch {
    return null;
  }
}

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('hex');
}

function makePassword(password) {
  const salt = randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}

function verifyPassword(password, owner) {
  if (!owner?.salt || !owner?.hash) return false;
  const actual = Buffer.from(hashPassword(password, owner.salt), 'hex');
  const expected = Buffer.from(owner.hash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function envOrThrow(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Lipsește secretul ${name}.`);
  return value;
}

async function supabaseFetch(env, table, query = '', options = {}) {
  const url = `${env.SUPABASE_URL.replace(/\\/$/, '')}/rest/v1/${table}${query}`;
  const headers = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    ...options.headers,
  };
  return fetch(url, { ...options, headers });
}

async function getOwner(env) {
  const r = await supabaseFetch(env, 'kronos_owner', '?id=eq.1&select=id,username,salt,password_hash,created_at');
  if (!r.ok) throw new Error(`Supabase owner GET ${r.status}: ${await r.text()}`);
  const rows = await r.json();
  if (!rows.length) return null;
  const row = rows[0];
  return { username: row.username, salt: row.salt, hash: row.password_hash, createdAt: row.created_at };
}

async function getData(env) {
  const r = await supabaseFetch(env, 'kronos_state', '?id=eq.1&select=data');
  if (!r.ok) throw new Error(`Supabase state GET ${r.status}: ${await r.text()}`);
  const rows = await r.json();
  return normalizeData(rows[0]?.data);
}

async function saveData(env, data) {
  const r = await supabaseFetch(env, 'kronos_state', '?id=eq.1', {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({ data: normalizeData(data), updated_at: new Date().toISOString() }),
  });
  if (!r.ok) throw new Error(`Supabase state PATCH ${r.status}: ${await r.text()}`);
  const rows = await r.json();
  return rows[0]?.updated_at || new Date().toISOString();
}

async function createOwner(env, username, salt, hash) {
  const r = await supabaseFetch(env, 'kronos_owner', '', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify({ id: 1, username, salt, password_hash: hash }),
  });
  if (!r.ok) throw new Error(`Supabase owner POST ${r.status}: ${await r.text()}`);
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > 2_000_000) throw new Error('Payload prea mare.');
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new Error('JSON invalid.');
  }
}

function authenticated(request, env) {
  return getSession(request, env.SESSION_SECRET);
}

export default {
  async fetch(request, env) {
    try {
      envOrThrow(env, 'SUPABASE_URL');
      envOrThrow(env, 'SUPABASE_SERVICE_ROLE_KEY');
      envOrThrow(env, 'SESSION_SECRET');

      const url = new URL(request.url);

      if (url.pathname.startsWith('/api/')) {
        if (request.method === 'GET' && url.pathname === '/api/status') {
          const owner = await getOwner(env);
          const session = authenticated(request, env);
          return json({
            setupRequired: !owner,
            authenticated: !!session,
            username: session?.username || null,
            database: 'supabase',
          });
        }

        if (request.method === 'POST' && url.pathname === '/api/setup') {
          const owner = await getOwner(env);
          if (owner) return json({ error: 'Contul Owner există deja.' }, 409);
          const b = await readBody(request);
          const username = String(b.username || '').trim();
          const password = String(b.password || '');
          if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return json({ error: 'Username invalid.' }, 400);
          if (password.length < 10) return json({ error: 'Parola trebuie să aibă cel puțin 10 caractere.' }, 400);
          const p = makePassword(password);
          try {
            await createOwner(env, username, p.salt, p.hash);
          } catch (e) {
            const current = await getOwner(env);
            if (current) return json({ error: 'Contul Owner există deja.' }, 409);
            throw e;
          }
          const token = createSession(username, env.SESSION_SECRET);
          return json({ ok: true }, 200, { 'Set-Cookie': cookie(token, SESSION_TTL) });
        }

        if (request.method === 'POST' && url.pathname === '/api/login') {
          const owner = await getOwner(env);
          if (!owner) return json({ error: 'Contul Owner nu este configurat.' }, 428);
          const b = await readBody(request);
          if (String(b.username || '') !== owner.username || !verifyPassword(String(b.password || ''), owner)) {
            return json({ error: 'Date de autentificare incorecte.' }, 401);
          }
          const token = createSession(owner.username, env.SESSION_SECRET);
          return json({ ok: true }, 200, { 'Set-Cookie': cookie(token, SESSION_TTL) });
        }

        if (request.method === 'POST' && url.pathname === '/api/logout') {
          return json({ ok: true }, 200, { 'Set-Cookie': cookie('', 0) });
        }

        if (request.method === 'GET' && url.pathname === '/api/public-data') {
          return json(await getData(env));
        }

        if (request.method === 'GET' && url.pathname === '/api/data') {
          if (!authenticated(request, env)) return json({ error: 'Neautorizat.' }, 401);
          return json(await getData(env));
        }

        if (request.method === 'POST' && url.pathname === '/api/data') {
          if (!authenticated(request, env)) return json({ error: 'Neautorizat.' }, 401);
          const b = await readBody(request);
          if (!b || typeof b !== 'object' || !b.events || !b.rules || !Array.isArray(b.customEvents || []) || !Array.isArray(b.customRules || [])) {
            return json({ error: 'Date invalide.' }, 400);
          }
          const savedAt = await saveData(env, b);
          return json({ ok: true, savedAt });
        }

        if (request.method === 'POST' && url.pathname === '/api/reset') {
          if (!authenticated(request, env)) return json({ error: 'Neautorizat.' }, 401);
          await saveData(env, EMPTY_DATA);
          return json({ ok: true });
        }

        return json({ error: 'Endpoint inexistent.' }, 404);
      }

      // Static frontend: HTML/CSS/JS/images are served by Workers Static Assets.
      return env.ASSETS.fetch(request);
    } catch (e) {
      console.error(e);
      return json({ error: 'Eroare server.', detail: String(e?.message || e) }, 500);
    }
  },
};
