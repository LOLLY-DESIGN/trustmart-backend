# TRUSTMART⭐ Splash + backend starter

This package connects the splash screen to a Node.js API and PostgreSQL-backed account/session service. The splash design is preserved. **It is a starter implementation, not a deployed/live backend yet.**

## What is included
- `public/index.html`: updated splash/welcome prototype.
- `server.js`: health check, registration, login, session verification, logout.
- `schema.sql`: users table.
- `.env.example`: required server/database settings.

## Run locally
1. Install Node.js 20 or newer and PostgreSQL.
2. Create a database named `trustmart`.
3. Run the SQL in `schema.sql` against that database.
4. Copy `.env.example` to `.env`; set `DATABASE_URL` and a random `JWT_SECRET` (32+ characters). Keep `.env` private.
5. Run `npm install`, then `npm start`.
6. Open `http://localhost:3000` (do not open `index.html` as a `file://` URL).

## Important status and limitations
- The splash waits at least 3 seconds, then checks `/api/health` and `/api/auth/session`. A valid session opens Home. A first-time visitor with no saved session goes to Welcome. If a previously signed-in user cannot be verified, the app asks them to log in again. A slow or unavailable service leaves the splash on screen with a retry option for visitors without a saved session.
- Registration/login endpoints use bcrypt password hashing and an HTTP-only session cookie. This is a first implementation and still needs production security review, rate limiting, email verification, password reset, abuse monitoring, backups, and deployment configuration before real users.
- Offline fallback only shows a locally saved-session view and cached UI. It cannot securely verify that a server session remains valid while offline, and it does not yet cache marketplace data.
- The existing HTML welcome page still has prototype marketplace features. The real account modal can register/login against this API when served by the backend.
- A real deployment requires a PostgreSQL database, hosting, environment secrets, HTTPS, and an authorized deployment action. None are provisioned by this package.
