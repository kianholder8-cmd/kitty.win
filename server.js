import './lib/env.js';

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

import {
  createPasswordUser,
  findUserByEmail,
  findUserById,
  upsertGoogleUser,
} from './lib/store.js';
import { hashPassword, verifyPassword } from './lib/password.js';
import {
  clearSessionCookie,
  parseCookies,
  readSession,
  safeEqual,
  setSessionCookie,
} from './lib/session.js';
import { exchangeCode, fetchProfile, googleAuthUrl, googleConfigured } from './lib/google.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;
const APP_URL = process.env.APP_URL?.trim().replace(/\/+$/, '') || '';

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
  );
  next();
});

app.use(express.json({ limit: '8kb' }));
app.use(
  express.static(PUBLIC_DIR, {
    index: false,
    maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0,
  })
);

function selfOrigin(req) {
  return `${req.protocol}://${req.get('host')}`;
}

function publicOrigin(req) {
  return APP_URL || selfOrigin(req);
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function isEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function noticePage(title, detail) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} | kitty.win</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<div class="shell">
<main class="card">
<p class="eyebrow">kitty.win</p>
<h1>${escapeHtml(title)}</h1>
<p class="sub">${escapeHtml(detail)}</p>
<p class="switch"><a href="/signup">Back to sign up</a></p>
</main>
</div>
</body>
</html>`;
}

const attempts = new Map();
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const ATTEMPT_LIMIT = 25;

function throttle(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();

  if (attempts.size > 2000) {
    for (const [ip, entry] of attempts) {
      if (now - entry.start > ATTEMPT_WINDOW_MS) attempts.delete(ip);
    }
  }

  const entry = attempts.get(key);
  if (!entry || now - entry.start > ATTEMPT_WINDOW_MS) {
    attempts.set(key, { start: now, count: 1 });
    return next();
  }

  entry.count += 1;
  if (entry.count > ATTEMPT_LIMIT) {
    return res.status(429).json({ error: 'Too many attempts. Wait a few minutes and try again.' });
  }
  next();
}

const api = express.Router();

api.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const origin = req.get('origin');
    if (origin && origin !== selfOrigin(req)) {
      return res.status(403).json({ error: 'Cross-origin request blocked.' });
    }
  }

  next();
});

api.post('/signup', throttle, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (password.length > 200) {
      return res.status(400).json({ error: 'That password is too long.' });
    }

    if (await findUserByEmail(email)) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const passwordHash = await hashPassword(password);
    const user = await createPasswordUser({ email, passwordHash });
    setSessionCookie(req, res, user);
    return res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === 'EMAIL_TAKEN') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    return next(err);
  }
});

api.post('/signin', throttle, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isEmail(email) || !password) {
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }

    const user = await findUserByEmail(email);
    if (user && !user.passwordHash) {
      return res
        .status(400)
        .json({ error: 'That account uses Google sign-in. Continue with Google instead.' });
    }

    const valid = user ? await verifyPassword(password, user.passwordHash) : false;
    if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' });

    setSessionCookie(req, res, user);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

api.get('/me', async (req, res, next) => {
  try {
    const session = readSession(req);
    if (!session) return res.status(401).json({ error: 'Not signed in.' });

    const user = await findUserById(session.sub);
    if (!user) return res.status(401).json({ error: 'Not signed in.' });

    return res.json({ email: user.email, name: user.name });
  } catch (err) {
    return next(err);
  }
});

api.post('/signout', (req, res) => {
  clearSessionCookie(req, res);
  res.status(204).end();
});

app.use('/api', api);

app.get(['/', '/signup', '/signin'], (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/welcome', (req, res) => {
  if (!readSession(req)) return res.redirect('/signup');
  res.sendFile(path.join(PUBLIC_DIR, 'welcome.html'));
});

app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

const OAUTH_COOKIE = 'kw_oauth';

function oauthCookieOptions(req) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: Boolean(req.secure) || APP_URL.startsWith('https://'),
    path: '/auth/google',
  };
}

app.get('/auth/google', (req, res) => {
  if (!googleConfigured()) {
    return res
      .status(503)
      .type('html')
      .send(
        noticePage(
          'Google sign-in is not set up yet',
          'This server needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET before Google sign-in can work.'
        )
      );
  }

  const state = crypto.randomBytes(24).toString('base64url');
  res.cookie(OAUTH_COOKIE, state, { ...oauthCookieOptions(req), maxAge: 10 * 60 * 1000 });
  res.redirect(googleAuthUrl({ origin: publicOrigin(req), state }));
});

app.get('/auth/google/callback', async (req, res) => {
  const fail = (code) => res.redirect(`/signup?error=${encodeURIComponent(code)}`);

  if (!googleConfigured()) return fail('google_not_configured');

  const { code, state } = req.query;
  const expected = parseCookies(req)[OAUTH_COOKIE];
  res.clearCookie(OAUTH_COOKIE, oauthCookieOptions(req));

  if (
    typeof code !== 'string' ||
    typeof state !== 'string' ||
    !expected ||
    !safeEqual(state, expected)
  ) {
    return fail('google_state');
  }

  try {
    const tokens = await exchangeCode({
      code,
      redirectUri: `${publicOrigin(req)}/auth/google/callback`,
    });
    const profile = await fetchProfile(tokens.access_token);

    if (!profile?.email || profile.email_verified !== true) return fail('google_email');

    const user = await upsertGoogleUser({
      email: normalizeEmail(profile.email),
      name: typeof profile.name === 'string' ? profile.name.slice(0, 80) : null,
      googleId: typeof profile.sub === 'string' ? profile.sub : null,
    });

    setSessionCookie(req, res, user);
    return res.redirect('/welcome');
  } catch (err) {
    console.error('[google] sign-in failed:', err.message);
    return fail('google_failed');
  }
});

app.use((req, res) => {
  res.status(404).type('html').send(noticePage('Page not found', 'That page does not exist.'));
});

app.use((err, req, res, next) => {
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed request.' });
  }

  console.error('[server]', err);

  if (res.headersSent) return next(err);
  const isApi = req.path.startsWith('/api/');
  if (isApi) return res.status(500).json({ error: 'Something went wrong on our end.' });
  res.status(500).type('html').send(noticePage('Something went wrong', 'Try again in a minute.'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`kitty.win listening on port ${PORT}`);
  if (APP_URL) console.log(`public origin: ${APP_URL}`);
  if (!process.env.SESSION_SECRET) {
    console.warn('[auth] SESSION_SECRET is not set. Sessions will reset on every restart.');
  }
  if (!googleConfigured()) {
    console.warn(
      '[auth] Google sign-in is off. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable it.'
    );
  }
});
