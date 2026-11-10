# kitty.win

Sign-up and sign-in for kitty.win. Email and password accounts plus Google sign-in.
It runs as a small Node service, so it deploys to Render as a normal Web Service.

## What is in here

- `server.js` handles pages, sessions, sign-up, sign-in and the Google OAuth flow.
- `lib/store.js` keeps accounts in `data/users.json` with atomic writes.
- `lib/password.js` hashes passwords with scrypt.
- `lib/session.js` signs a 30 day session cookie with HMAC.
- `public/` holds the sign-up screen, its styles and the signed-in page.

## Run it locally

```bash
npm install
npm start
```

Open http://localhost:3000.

A `.env` file is already set up for local use. For a fresh clone, copy `.env.example`
to `.env` and set a `SESSION_SECRET`.

## Turn on Google sign-in

1. Open https://console.cloud.google.com and create a project (or pick one).
2. Go to APIs and Services, then OAuth consent screen. Choose External, fill in the app
   name and your email, and save. While the app is in testing, add your Google account
   under Test users.
3. Go to APIs and Services, then Credentials, then Create credentials, then OAuth client ID.
4. Pick Web application and add these Authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback`
   - `https://YOUR-SITE.onrender.com/auth/google/callback`
5. Copy the client ID and client secret into the environment.

Google sign-in stays off, with a clear notice, until both values are set.

## Deploy on Render

The Render service already exists, so it only needs settings and environment variables.

Build command:

```
npm install
```

Start command:

```
npm start
```

Health check path:

```
/healthz
```

Environment variables:

| Name | Value |
| --- | --- |
| `SESSION_SECRET` | a long random string, at least 32 characters |
| `APP_URL` | `https://YOUR-SITE.onrender.com` (or your domain) |
| `GOOGLE_CLIENT_ID` | from Google Cloud |
| `GOOGLE_CLIENT_SECRET` | from Google Cloud |
| `DATA_DIR` | optional, see storage below |

Render provides `PORT` on its own. Do not set it there.

Generate a session secret with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Changing `SESSION_SECRET` signs everyone out.

## Storage

Accounts live in `DATA_DIR/users.json` (`data/` by default). On Render's free plan the
filesystem resets on deploy or restart, so accounts disappear. To keep them:

1. Add a Render Disk to the service, mounted at `/var/data`.
2. Set `DATA_DIR` to `/var/data`.

Disks are available on paid plans. If you outgrow a JSON file, move the three functions in
`lib/store.js` to Postgres. The rest of the app does not change.

## Security notes

- Passwords are hashed with scrypt and a per-user salt.
- Session cookies are HttpOnly, SameSite=Lax and Secure on HTTPS.
- Cookies are signed, and tampering is rejected.
- Sign-up and sign-in are rate limited per IP.
- A strict CSP is applied, and there are no inline scripts or styles.
- Cross-origin POSTs to the API are rejected.
