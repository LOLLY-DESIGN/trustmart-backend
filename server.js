require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');
const path = require('path');

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) {
  console.error('JWT_SECRET must be set to a random string of at least 32 characters.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Copy .env.example to .env and configure PostgreSQL.');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined });
const secureCookie = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const credentialsSchema = z.object({
  email: z.string().trim().email().max(254).transform(v => v.toLowerCase()),
  password: z.string().min(8).max(128)
});
function issueSession(res, user) {
  const token = jwt.sign({ sub: String(user.id), email: user.email }, jwtSecret, { expiresIn: '7d', issuer: 'trustmart-api', audience: 'trustmart-client' });
  res.cookie('trustmart_session', token, { httpOnly: true, secure: secureCookie, sameSite: 'lax', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function clearSession(res) { res.clearCookie('trustmart_session', { httpOnly: true, secure: secureCookie, sameSite: 'lax', path: '/' }); }
function readSession(req) {
  const token = req.cookies && req.cookies.trustmart_session;
  if (!token) return null;
  try { return jwt.verify(token, jwtSecret, { issuer: 'trustmart-api', audience: 'trustmart-client' }); }
  catch (_) { return null; }
}
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.set('Cache-Control', 'no-store').json({ ok: true, service: 'trustmart-api', database: 'reachable', timestamp: new Date().toISOString() }); }
  catch (_) { res.status(503).set('Cache-Control', 'no-store').json({ ok: false, error: 'Backend database unavailable' }); }
});
app.get('/api/auth/session', async (req, res) => {
  const claims = readSession(req);
  if (!claims) return res.set('Cache-Control', 'no-store').json({ authenticated: false });
  try {
    const result = await pool.query('SELECT id, email FROM users WHERE id = $1', [claims.sub]);
    if (!result.rowCount) { clearSession(res); return res.set('Cache-Control', 'no-store').json({ authenticated: false }); }
    return res.set('Cache-Control', 'no-store').json({ authenticated: true, user: result.rows[0] });
  } catch (_) { return res.status(503).set('Cache-Control', 'no-store').json({ error: 'Session verification unavailable' }); }
});
app.post('/api/auth/register', async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email and a password of 8–128 characters.' });
  const { email, password } = parsed.data;
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email', [email, passwordHash]);
    issueSession(res, result.rows[0]);
    return res.status(201).json({ authenticated: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    console.error('Registration failed:', err.message);
    return res.status(503).json({ error: 'Account service temporarily unavailable.' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email and password.' });
  try {
    const result = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [parsed.data.email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    issueSession(res, user);
    return res.json({ authenticated: true, user: { id: user.id, email: user.email } });
  } catch (err) { console.error('Login failed:', err.message); return res.status(503).json({ error: 'Account service temporarily unavailable.' }); }
});
app.post('/api/auth/logout', (_req, res) => { clearSession(res); res.json({ ok: true }); });
app.use('/api', (_req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(port, () => console.log(`TrustMart backend listening on port ${port}`));
