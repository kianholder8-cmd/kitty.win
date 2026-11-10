import './env.js';

import crypto from 'node:crypto';

const COOKIE_NAME = 'kw_session';
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const secret = process.env.SESSION_SECRET?.trim() || crypto.randomBytes(32).toString('hex');

function isSecure(req) {
  return Boolean(req.secure) || (process.env.APP_URL || '').trim().startsWith('https://');
}

function baseOptions(req) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecure(req),
    path: '/',
  };
}

export function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};

  const cookies = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      cookies[name] = part.slice(index + 1).trim();
    }
  }
  return cookies;
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function setSessionCookie(req, res, user) {
  const now = Date.now();
  const payload = Buffer.from(
    JSON.stringify({ sub: user.id, iat: now, exp: now + MAX_AGE_MS })
  ).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');

  res.cookie(COOKIE_NAME, `${payload}.${signature}`, {
    ...baseOptions(req),
    maxAge: MAX_AGE_MS,
  });
}

export function readSession(req) {
  const raw = parseCookies(req)[COOKIE_NAME];
  if (!raw) return null;

  const index = raw.lastIndexOf('.');
  if (index < 1) return null;

  const payload = raw.slice(0, index);
  const signature = raw.slice(index + 1);
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');

  if (!safeEqual(signature, expected)) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.sub !== 'string') return null;
    if (typeof data.exp !== 'number' || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

export function clearSessionCookie(req, res) {
  res.clearCookie(COOKIE_NAME, baseOptions(req));
}
