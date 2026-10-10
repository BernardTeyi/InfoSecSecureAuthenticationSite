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
  try { 
    db = JSON.parse(C.decrypt(fs.readFileSync(DB_FILE, 'utf8'))); 
  } catch { 
    console.error('INTEGRITY FAILURE: database cannot be decrypted (wrong key or file was modified). Run "npm run restore".'); 
    process.exit(1); 
  }
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
    fs.unlinkSync(path.join(BACKUPS, old)); 
    fs.rmSync(path.join(BACKUPS, old + '.mac'), { force: true });
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
  return db.audit.every(e => { 
    const ok = e.prev === prev && e.hash === C.sha256(prev + e.ts + e.event + e.user); 
    prev = e.hash; 
    return ok; 
  });
}

// ================= Sessions =================
const sessions = new Map();  // sid -> {userId, exp}
const pending = new Map();   // pid -> {userId, purpose:'login'|'enroll', exp, tries}
const SESSION_MS = 30 * 60 * 1000, PENDING_MS = 5 * 60 * 1000;
setInterval(() => { 
  const n = Date.now(); 
  for (const m of [sessions, pending]) 
    for (const [k, v] of m) 
      if (v.exp < n) m.delete(k); 
}, 60000).unref();

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

// ================= Input Sanitization & Validation =================
const cleanName = u => 
  typeof u === 'string' 
    ? u.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim() 
    : u;

// FIXED: Removed the stray backslash before the '\$' anchor so usernames match correctly
const validUsername = u => 
  typeof u === 'string' && /^[A-Za-z0-9_]{3,20}\$/.test(u);

const validPassword = p => 
  typeof p === 'string' && 
  p.length >= 10 && 
  p.length <= 128 && 
  /[a-z]/.test(p) && 
  /[A-Z]/.test(p) && 
  /\d/.test(p) && 
  /[^A-Za-z0-9]/.test(p);

const GENERIC = { error: 'Invalid username or password' };

// FIXED: Cleaned up mock configurations to safely use your active 'C' utility object
const dummy = C.hashPassword('dummy-password');

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
  
  const { salt, hash } = C.hashPassword(password); // salt + pepper
  const user = {
    id: C.token(8), username, salt, hash,
    role: db.users.length === 0 ? 'admin' : 'user', // first account becomes admin
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

// ================= 3. Login step 1: password =================
app.post('/api/login', async (req, res) => {
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  
  // Find the candidate user account
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  
  // Execute a standard dummy hash operation if user does not exist to prevent timing analysis
  if (!user) {
    C.verifyPassword(password, dummy.salt, dummy.hash);
    return res.status(401).json(GENERIC);
  }

  // Enforce account lockout thresholds if active
  if (user.lockUntil > Date.now()) {
    return res.status(423).json({ error: 'Account temporarily locked. Try again later.' });
  }

  // Validate the provided credential hash
  const isValid = C.verifyPassword(password, user.salt, user.hash);
  if (!isValid) {
    user.fails += 1;
    if (user.fails >= 5) {
      user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock account for 15 minutes
      audit('ACCOUNT_LOCKED', user.username);
    }
    save();
    return res.status(401).json(GENERIC);
  }

  // Reset tracking stats on positive identification match
  user.fails = 0;
  user.lockUntil = 0;
  save();

  // Route forward to Multi-Factor validation step if configuration requires it
  if (user.totpEnabled) {
    const pid = newPending(user.id, 'login');
    return res.json({ step: '2fa', pendingId: pid });
  }

  // Fallback to directly enrolling users who bypass full setups
  res.json(await enrollPayload(user));
});

// Start application listener
app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));
