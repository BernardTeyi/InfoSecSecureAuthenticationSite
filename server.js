'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./crypto-utils');

const PORT = process.env.PORT || 3000;
const DATA = path.join('/tmp', 'data'); 
const DB_FILE = path.join(DATA, 'db.enc');

try {
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
} catch (e) {
  console.error("Directory initialization bypassed:", e.message);
}

// ================= Encrypted database =================
let db = { users: [], audit: [] };

function loadDatabase() {
  if (fs.existsSync(DB_FILE)) {
    try { 
      db = JSON.parse(C.decrypt(fs.readFileSync(DB_FILE, 'utf8'))); 
    } catch (err) { 
      db = { users: [], audit: [] };
    }
  }
}
loadDatabase();

function save() {
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, C.encrypt(JSON.stringify(db)), { mode: 0o600 });
    fs.renameSync(tmp, DB_FILE);
  } catch (err) {
    console.error('Storage save warning:', err.message);
  }
}

// ================= Tamper-evident audit log =================
function audit(event, user = '-') {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].hash : 'GENESIS';
  const entry = { ts: new Date().toISOString(), event, user, prev };
  entry.hash = C.sha256(prev + entry.ts + event + user);
  db.audit.push(entry);
}

// ================= Sessions =================
const sessions = new Map();  
const pending = new Map();   
const SESSION_MS = 30 * 60 * 1000, PENDING_MS = 5 * 60 * 1000;

const purge = (userId, except) => { for (const [k, v] of sessions) if (v.userId === userId && k !== except) sessions.delete(k); };
const newPending = (userId, purpose) => { const id = C.token(); pending.set(id, { userId, purpose, exp: Date.now() + PENDING_MS, tries: 0 }); return id; };
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(p => p)); }

// ================= App + middleware =================
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'
  });
  next();
});

// --- Authentication guard
function requireAuth(req, res, next) {
  loadDatabase();
  const s = sessions.get(cookies(req).sid);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Not logged in' });
  const user = db.users.find(u => u.id === s.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  s.exp = Date.now() + SESSION_MS; req.user = user; next();
}

// ================= Input Sanitization & Validation =================
const cleanName = u => typeof u === 'string' ? u.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim() : u;

// FIXED COMPLETED: Fixed the username check pattern (\$ anchor is completely cleared of any stray backslashes)
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);



const validPassword = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const GENERIC = { error: 'Invalid username or password' };
const dummy = C.hashPassword('dummy-password');

async function enrollPayload(user) {
  const uri = `otpauth://totp/SecureAuth:${encodeURIComponent(user.username)}?secret=${user.totpSecret}&issuer=SecureAuth&digits=6&period=30`;
  return { step: 'enroll', pendingId: newPending(user.id, 'enroll'), secret: user.totpSecret, qr: await QRCode.toDataURL(uri) };
}

// ================= Built-in Landing Page Route =================
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>Secure Auth API</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px; background:#f4f6f9; color:#333;">
        <h1>🔒 Secure Authentication API</h1>
        <p style="color:#666;">The API endpoint is online and healthy.</p>
        <div style="margin-top:20px; font-size:14px; color:#888;">Endpoints active: /api/register | /api/login | /api/2fa/verify</div>
      </body>
    </html>
  `);
});

// ================= 1. Identification: register =================
app.post('/api/register', async (req, res) => {
  loadDatabase();
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  
  if (!validUsername(username)) return res.status(400).json({ error: 'Username must be 3-20 characters: letters, numbers or underscore (no spaces)' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password: 10+ characters with upper, lower, number and symbol' });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username already taken' });
  
  const { salt, hash } = C.hashPassword(password);
  const user = {
    id: C.token(8), username, salt, hash,
    role: db.users.length === 0 ? 'admin' : 'user',
    totpSecret: C.newTotpSecret(), totpEnabled: false, lastStep: 0, fails: 0, lockUntil: 0, created: new Date().toISOString()
  };
  db.users.push(user); audit('REGISTER', username); save();
  res.json(await enrollPayload(user));
});

// ================= 2. Two-factor: activate (enrol) =================
app.post('/api/2fa/activate', (req, res) => {
  loadDatabase();
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
  loadDatabase();
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  
  if (!user) {
    C.verifyPassword(password, dummy.salt, dummy.hash);
    return res.status(401).json(GENERIC);
  }
  if (user.lockUntil > Date.now()) {
    return res.status(423).json({ error: 'Account temporarily locked. Try again later.' });
  }

  const isValid = C.verifyPassword(password, user.salt, user.hash);
  if (!isValid) {
    user.fails += 1;
    if (user.fails >= 5) {
      user.lockUntil = Date.now() + 15 * 60 * 1000;
      audit('ACCOUNT_LOCKED', user.username);
    }
    save();
    return res.status(401).json(GENERIC);
  }

  user.fails = 0; user.lockUntil = 0; save();

  if (user.totpEnabled) {
    const pid = newPending(user.id, 'login');
    return res.json({ step: '2fa', pendingId: pid });
  }
  res.json(await enrollPayload(user));
});

// ================= 4. Two-factor: verify login =================
app.post('/api/2fa/verify', (req, res) => {
  loadDatabase();
  const p = pending.get(req.body?.pendingId);
  if (!p || p.purpose !== 'login' || p.exp < Date.now()) return res.status(401).json({ error: 'Session expired' });
  
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(401).json({ error: 'Session expired' });
  
  const step = C.checkTotp(user.totpSecret, req.body.code, user.lastStep);
  if (!step) return res.status(401).json({ error: 'Wrong code' });
  
  user.lastStep = step; save(); pending.delete(req.body.pendingId);
  purge(user.id); 
  
  const sid = C.token();
  sessions.set(sid, { userId: user.id, exp: Date.now() + SESSION_MS });
  audit('LOGIN_SUCCESS', user.username);
  
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${30 * 60}`);
  res.json({ ok: true, role: user.role, username: user.username });
});

// ================= 5. Logout =================
app.post('/api/logout', (req, res) => {
  const sid = cookies(req).sid;
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));
