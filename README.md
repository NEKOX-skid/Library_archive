# Library Archive

A private, invite-only media library for resources you own or are authorized to share.

## Security features

- Invite-code-only account creation
- Configurable admin email via environment variable
- 12+ character passwords with bcrypt hashing
- Session regeneration after login/signup
- SQLite-backed persistent sessions
- CSRF protection for state-changing API requests
- Login/signup rate limiting
- Secure HTTP response headers and Content Security Policy
- HttpOnly + SameSite session cookies
- HTTPS-aware secure cookies in production
- Input length validation
- Server-side authorization for admin actions
- SSRF protections for admin link checking
- Private/local IP targets blocked during link checks
- No media files stored in the Git repository

## Categories

Anime, Games, Series, Movies, Music, Other.

## Production environment

Set strong, unique secrets on the hosting provider:

```
NODE_ENV=production
SESSION_SECRET=<long-random-secret>
INVITE_CODE=<long-random-private-invite>
ADMIN_EMAIL=<your-admin-email>
DB_PATH=/persistent-data/library.db
TRUST_PROXY=1
```

Use a persistent disk for `DB_PATH` and `sessions.sqlite`. Never commit secrets, database files, or real passwords to Git.

The first account is **not** automatically made admin. The account whose email matches `ADMIN_EMAIL` becomes admin.

## Run locally

```bash
npm install
NODE_ENV=development SESSION_SECRET="local-random-secret" INVITE_CODE="local-invite" ADMIN_EMAIL="you@example.com" npm start
```

Only add media resources you own or are authorized to share.