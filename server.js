'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./crypto-utils');

const PORT = process.env.PORT || 3000;
const BACKUP_MINUTES = Number(process.env.BACKUP_MINUTES || 60);
const KEEP_BACKUPS = 10;
const DATA = path.join(__dirname, 'data');
const BACKUPS = path.join(DATA, 'backups');
const DB_FILE = path.join(DATA, 'db.enc');
fs.mkdirSync(BACKUPS, { recursive: true });

// ================= Encrypted database =================
let db = { users: [], audit: [] };
let dirty = false;
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(C.decrypt(fs.readFileSync(DB_FILE, 'utf8'))); }
  catch { console.error('INTEGRITY FAILURE: database cannot be decrypted (wrong key or file was modified). Run "npm run restore".'); process.exit(1); }
}
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, C.encrypt(JSON.stringify(db)), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE); // atomic replace: no half-written file
  dirty = true;
}

// ================= Auto-backup =================
function backup() {
  if (!fs.existsSync(DB_FILE)) return;
  const dest = path.join(BACKUPS, `db-${new Date().toISOString().replace(/[:.]/g, '-')}.enc`);
  fs.copyFileSync(DB_FILE, dest);
  fs.writeFileSync(dest + '.mac', C.mac(fs.readFileSync(dest))); // integrity signature
  const files = fs.readdirSync(BACKUPS).filter(f => f.endsWith('.enc')).sort();
  for (const old of files.slice(0, Math.max(0, files.length - KEEP_BACKUPS))) {
    fs.unlinkSync(path.join(BACKUPS, old)); fs.rmSync(path.join(BACKUPS, old + '.mac'), { force: true });
  }
  dirty = false;
  console.log('[backup] saved', path.basename(dest));
}
backup();
setInterval(() => { if (dirty) backup(); }, BACKUP_MINUTES * 60 * 1000).unref();
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (dirty) backup(); process.exit(0); });

// ================= Tamper-evident audit log (hash chain) =================
function audit(event, user = '-') {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].hash : 'GENESIS';
  const entry = { ts: new Date().toISOString(), event, user, prev };
  entry.hash = C.sha256(prev + entry.ts + event + user);
  db.audit.push(entry);
}
function auditIntact() {
  let prev = 'GENESIS';
  return db.audit.every(e => { const ok = e.prev === prev && e.hash === C.sha256(prev + e.ts + e.event + e.user); prev = e.hash; return ok; });
}

// ================= Sessions =================
const sessions = new Map();  // sid -> {userId, exp}
const pending = new Map();   // pid -> {userId, purpose:'login'|'enroll', exp, tries}
const SESSION_MS = 30 * 60 * 1000, PENDING_MS = 5 * 60 * 1000;
setInterval(() => { const n = Date.now(); for (const m of [sessions, pending]) for (const [k, v] of m) if (v.exp < n) m.delete(k); }, 60000).unref();

const purge = (userId, except) => { for (const [k, v] of sessions) if (v.userId === userId && k !== except) sessions.delete(k); };
const newPending = (userId, purpose) => { const id = C.token(); pending.set(id, { userId, purpose, exp: Date.now() + PENDING_MS, tries: 0 }); return id; };
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(p => p[0])); }

// ================= App + middleware =================
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'
  });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// --- Authentication guard
function requireAuth(req, res, next) {
  const s = sessions.get(cookies(req).sid);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Not logged in' });
  const user = db.users.find(u => u.id === s.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  s.exp = Date.now() + SESSION_MS; req.user = user; next();
}
// --- Authorization guard (role-based)
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : (audit(`DENIED ${req.method} ${req.path}`, req.user.username), save(), res.status(403).json({ error: 'Forbidden: insufficient role' }));

const validPassword = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
// Phone keyboards often add a trailing space or invisible character; strip them before checking.
const cleanName = u => typeof u === 'string' ? u.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim() : u;
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);
const GENERIC = { error: 'Invalid username or password' };
const dummy = C.hashPassword('dummy-password'); // equalises timing for unknown users

async function enrollPayload(user) {
  const uri = `otpauth://totp/SecureAuth:${encodeURIComponent(user.username)}?secret=${user.totpSecret}&issuer=SecureAuth&digits=6&period=30`;
  return { step: 'enroll', pendingId: newPending(user.id, 'enroll'), secret: user.totpSecret, qr: await QRCode.toDataURL(uri) };
}

// ================= 1. Identification: register =================
app.post('/api/register', async (req, res) => {
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  if (!validUsername(username)) return res.status(400).json({ error: 'Username must be 3-20 characters: letters, numbers or underscore (no spaces)' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password: 10+ characters with upper, lower, number and symbol' });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username already taken' });
  const { salt, hash } = C.hashPassword(password);              // salt + pepper
  const user = {
    id: C.token(8), username, salt, hash,
    role: db.users.length === 0 ? 'admin' : 'user',              // first account becomes admin
    totpSecret: C.newTotpSecret(), totpEnabled: false, lastStep: 0, fails: 0, lockUntil: 0, created: new Date().toISOString()
  };
  db.users.push(user); audit('REGISTER', username); save();
  res.json(await enrollPayload(user));
});

// ================= 2. Two-factor: activate (enrol) =================
app.post('/api/2fa/activate', (req, res) => {
  const p = pending.get(req.body?.pendingId);
  if (!p || p.purpose !== 'enroll' || p.exp < Date.now()) return res.status(400).json({ error: 'Session expired, log in again' });
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(400).json({ error: 'Session expired, log in again' });
  const step = C.checkTotp(user.totpSecret, req.body.code, user.lastStep);
  if (!step) return res.status(401).json({ error: 'Wrong code' });
  user.totpEnabled = true; user.lastStep = step; pending.delete(req.body.pendingId);
  audit('2FA_ENABLED', user.username); save();
  res.json({ ok: true });
});

// ================= Login step 1: password =================
app.post('/api/login', async (req, res) => {
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  const user = db.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (user && user.lockUntil > Date.now()) return res.status(429).json({ error: 'Account locked for a few minutes after too many attempts' });
  const ok = user ? C.verifyPassword(String(password), user.salt, user.hash) : (C.verifyPassword(String(password), dummy.salt, dummy.hash), false);
  if (!ok) {
    if (user && ++user.fails >= 5) { user.lockUntil = Date.now() + 5 * 60 * 1000; user.fails = 0; audit('LOCKOUT', user.username); }
    audit('LOGIN_FAIL', user ? user.username : String(username).slice(0, 20)); save();
    return res.status(401).json(GENERIC);
  }
  user.fails = 0;
  if (!user.totpEnabled) return res.json(await enrollPayload(user)); // finish 2FA setup first
  res.json({ step: '2fa', pendingId: newPending(user.id, 'login') });
});

// ================= Login step 2: TOTP =================
app.post('/api/login/2fa', (req, res) => {
  const p = pending.get(req.body?.pendingId);
  if (!p || p.purpose !== 'login' || p.exp < Date.now()) return res.status(400).json({ error: 'Session expired, log in again' });
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(400).json({ error: 'Session expired, log in again' });
  const step = C.checkTotp(user.totpSecret, req.body.code, user.lastStep);
  if (!step) {
    if (++p.tries >= 5) pending.delete(req.body.pendingId);
    audit('2FA_FAIL', user.username); save();
    return res.status(401).json({ error: 'Wrong code' });
  }
  user.lastStep = step; pending.delete(req.body.pendingId);
  const sid = C.token(); sessions.set(sid, { userId: user.id, exp: Date.now() + SESSION_MS });
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: SESSION_MS });
  user.lastLogin = new Date().toISOString();
  audit('LOGIN_OK', user.username); save();
  res.json({ ok: true });
});

app.post('/api/logout', requireAuth, (req, res) => { sessions.delete(cookies(req).sid); res.clearCookie('sid'); audit('LOGOUT', req.user.username); save(); res.json({ ok: true }); });

// ================= 3. Authorization by role =================
app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.user.username, role: req.user.role, created: req.user.created, lastLogin: req.user.lastLogin || null, twoFactor: req.user.totpEnabled }));
app.get('/api/user/area', requireAuth, requireRole('user', 'admin'), (req, res) => res.json({ message: `Welcome ${req.user.username}. This area is open to the roles: user and admin.` }));

app.get('/api/admin/users', requireAuth, requireRole('admin'), (req, res) =>
  res.json(db.users.map(u => ({ id: u.id, username: u.username, role: u.role, twoFactor: u.totpEnabled, created: u.created, lastLogin: u.lastLogin || null, locked: u.lockUntil > Date.now() }))));
app.post('/api/admin/users/:id/role', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  if (!['user', 'admin'].includes(req.body?.role)) return res.status(400).json({ error: 'Role must be user or admin' });
  if (t.id === req.user.id) return res.status(400).json({ error: 'You cannot change your own role' });
  t.role = req.body.role; audit(`ROLE ${t.username}=${t.role}`, req.user.username); save(); res.json({ ok: true });
});
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const i = db.users.findIndex(u => u.id === req.params.id);
  if (i < 0 || db.users[i].id === req.user.id) return res.status(400).json({ error: 'Bad request' });
  audit(`DELETE_USER ${db.users[i].username}`, req.user.username); purge(db.users[i].id); db.users.splice(i, 1); save(); res.json({ ok: true });
});
app.get('/api/admin/audit', requireAuth, requireRole('admin'), (req, res) => res.json({ chainIntact: auditIntact(), entries: db.audit.slice(-50).reverse() }));
app.post('/api/admin/backup', requireAuth, requireRole('admin'), (req, res) => { backup(); audit('MANUAL_BACKUP', req.user.username); save(); res.json({ ok: true }); });


// ---- Extra admin tools
app.post('/api/admin/users/:id/unlock', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  t.lockUntil = 0; t.fails = 0; audit(`UNLOCK ${t.username}`, req.user.username); save(); res.json({ ok: true });
});
app.post('/api/admin/users/:id/reset-2fa', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  if (t.id === req.user.id) return res.status(400).json({ error: 'You cannot reset your own 2FA' });
  t.totpSecret = C.newTotpSecret(); t.totpEnabled = false; t.lastStep = 0; purge(t.id); // forces fresh enrolment at next login
  audit(`RESET_2FA ${t.username}`, req.user.username); save(); res.json({ ok: true });
});

// ---- Any logged-in user: change own password
app.post('/api/account/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const u = req.user;
  if (!C.verifyPassword(String(currentPassword), u.salt, u.hash)) {
    if (++u.fails >= 5) { u.lockUntil = Date.now() + 5 * 60 * 1000; u.fails = 0; purge(u.id); audit('LOCKOUT', u.username); }
    audit('PASSWORD_CHANGE_FAIL', u.username); save();
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (!validPassword(newPassword)) return res.status(400).json({ error: 'New password: 10+ characters with upper, lower, number and symbol' });
  if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must be different' });
  const { salt, hash } = C.hashPassword(newPassword);
  u.salt = salt; u.hash = hash; u.fails = 0;
  purge(u.id, cookies(req).sid); // sign out every other device
  audit('PASSWORD_CHANGED', u.username); save(); res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Secure auth running at http://localhost:${PORT}`));
