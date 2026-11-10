import './env.js';

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const DATA_DIR = process.env.DATA_DIR?.trim() || path.join(process.cwd(), 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

let users = null;
let queue = Promise.resolve();

function serialize(task) {
  const run = queue.then(task);
  queue = run.then(
    () => {},
    () => {}
  );
  return run;
}

async function load() {
  if (users) return users;

  try {
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.users)) throw new Error('users.json has an unexpected shape');
    users = parsed.users;
  } catch (err) {
    if (err.code === 'ENOENT') {
      users = [];
    } else {
      throw err;
    }
  }

  return users;
}

async function writeSnapshot() {
  const snapshot = JSON.stringify({ users }, null, 2);
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temp = `${USERS_FILE}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(temp, snapshot, { mode: 0o600 });
  await fs.rename(temp, USERS_FILE);
}

function newUser(fields) {
  return {
    id: crypto.randomUUID(),
    email: fields.email,
    name: fields.name ?? null,
    provider: fields.provider,
    passwordHash: fields.passwordHash ?? null,
    googleId: fields.googleId ?? null,
    createdAt: new Date().toISOString(),
  };
}

export function findUserByEmail(email) {
  return load().then((list) => list.find((user) => user.email === email) || null);
}

export function findUserById(id) {
  return load().then((list) => list.find((user) => user.id === id) || null);
}

export function createPasswordUser({ email, passwordHash }) {
  return serialize(async () => {
    const list = await load();

    if (list.some((user) => user.email === email)) {
      const err = new Error('Email already registered');
      err.code = 'EMAIL_TAKEN';
      throw err;
    }

    const user = newUser({ email, passwordHash, provider: 'password' });
    list.push(user);
    await writeSnapshot();
    return user;
  });
}

export function upsertGoogleUser({ email, name, googleId }) {
  return serialize(async () => {
    const list = await load();
    const existing = list.find((user) => user.email === email);

    if (existing) {
      let changed = false;
      if (!existing.googleId && googleId) {
        existing.googleId = googleId;
        changed = true;
      }
      if (!existing.name && name) {
        existing.name = name;
        changed = true;
      }
      if (changed) await writeSnapshot();
      return existing;
    }

    const user = newUser({ email, name, googleId, provider: 'google' });
    list.push(user);
    await writeSnapshot();
    return user;
  });
}
