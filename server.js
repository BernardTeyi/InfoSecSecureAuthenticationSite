'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./crypto-utils');

const PORT = process.env.PORT || 3000;
const DATA = path.join('/tmp', 'data'); 
const DB_FILE = path.join(DATA, 'db.enc');

// Ensure database directory exists
try {
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
} catch (e) {
  console.error("Directory initialization bypassed:", e.message);
}


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

function audit(event, user = '-') {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].hash : 'GENESIS';
  const entry = { ts: new Date().toISOString(), event, user, prev };
  entry.hash = C.sha256(prev + entry.ts + event + user);
  db.audit.push(entry);
}


const sessions = new Map();  
const pending = new Map();   
const SESSION_MS = 30 * 60 * 1000, PENDING_MS = 5 * 60 * 1000;

const purge = (userId, except) => { for (const [k, v] of sessions) if (v.userId === userId && k !== except) sessions.delete(k); };
const newPending = (userId, purpose) => { const id = C.token(); pending.set(id, { userId, purpose, exp: Date.now() + PENDING_MS, tries: 0 }); return id; };
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(p => p)); }

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




const cleanName = u => typeof u === 'string' ? u.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim() : u;
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}\$/.test(u);
const validPassword = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const GENERIC = { error: 'Invalid username or password' };
const dummy = C.hashPassword('dummy-password');

async function enrollPayload(user) {
  const uri = `otpauth://totp/SecureAuth:${encodeURIComponent(user.username)}?secret=${user.totpSecret}&issuer=SecureAuth&digits=6&period=30`;
  return { step: 'enroll', pendingId: newPending(user.id, 'enroll'), secret: user.totpSecret, qr: await QRCode.toDataURL(uri) };
}





app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Secure Multi-Factor Portal</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .card { background: #ffffff; width: 100%; max-width: 420px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); padding: 32px; transition: all 0.3s ease; }
        h2 { color: #1a1a1a; margin-bottom: 8px; font-size: 24px; text-align: center; }
        .subtitle { color: #666; font-size: 14px; text-align: center; margin-bottom: 24px; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; font-weight: 600; color: #444; margin-bottom: 6px; }
        input { width: 100%; padding: 10px 14px; border: 1px solid #ccc; border-radius: 6px; font-size: 15px; outline: none; transition: border 0.2s; }
        input:focus { border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }
        button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 8px; }
        button:hover { background: #0052a3; }
        .toggle-link { text-align: center; margin-top: 16px; font-size: 14px; color: #0066cc; cursor: pointer; }
        .toggle-link:hover { text-decoration: underline; }
        .error-box { background: #ffebe9; border: 1px solid #ffc2bc; color: #cf222e; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; display: none; }
        .success-box { background: #dafbe1; border: 1px solid #8ce89f; color: #1a7f37; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; display: none; }
        .qr-container { text-align: center; margin: 20px 0; }
        .qr-container img { max-width: 180px; border: 4px solid #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .secret-badge { display: inline-block; background: #f6f8fa; border: 1px solid #d0d7de; padding: 4px 8px; font-family: monospace; border-radius: 4px; font-size: 13px; margin-top: 6px; color: #24292f; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <div id="errorBox" class="error-box"></div>
        <div id="successBox" class="success-box"></div>

        <div id="loginView">
          <h2>Welcome Back</h2>
          <p class="subtitle">Please login to access your account</p>
          <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="loginUser" required autocomplete="username">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" id="loginPass" required autocomplete="current-password">
            </div>
            <button type="submit">Sign In</button>
          </form>
          <div class="toggle-link" onclick="switchView('register')">Don't have an account? Register</div>
        </div>

        <div id="registerView" class="hidden">
          <h2>Create Account</h2>
          <p class="subtitle">Set up your secure authentication profile</p>
          <form id="registerForm" onsubmit="handleRegister(event)">
            <div class="form-group">
              <label>Username</label>
              <input type="text" id="regUser" placeholder="Letters, numbers, underscores" required autocomplete="username">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" id="regPass" placeholder="Min. 10 characters" required autocomplete="new-password">
            </div>
            <button type="submit">Register</button>
          </form>
          <div class="toggle-link" onclick="switchView('login')">Already registered? Sign In</div>
        </div>

        <div id="enrollView" class="hidden">
          <h2>Bind Authenticator</h2>
          <p class="subtitle">Scan this QR code with Google Authenticator or manual code input below:</p>
          <div class="qr-container">
            <img id="qrImage" src="" alt="MFA QR Code">
            <div><span id="secretKey" class="secret-badge"></span></div>
          </div>
          <form id="enrollForm" onsubmit="handle2FAActivate(event)">
            <input type="hidden" id="enrollPendingId">
            <div class="form-group">
              <label>Enter 6-Digit Verification Code</label>
              <input type="text" id="enrollCode" maxlength="6" placeholder="000000" pattern="\\d{6}" required>
            </div>
            <button type="submit">Activate 2FA Security</button>
          </form>
        </div>

        <div id="mfaChallengeView" class="hidden">
          <h2>Security Verification</h2>
          <p class="subtitle">Enter the dynamic token code from your phone app:</p>
          <form id="challengeForm" onsubmit="handle2FAVerify(event)">
            <input type="hidden" id="challengePendingId">
            <div class="form-group">
              <label>Authenticator Passcode</label>
              <input type="text" id="challengeCode" maxlength="6" placeholder="000000" pattern="\\d{6}" required autofocus>
            </div>
            <button type="submit">Confirm Code & Login</button>
          </form>
        </div>

        <div id="dashboardView" class="hidden">
          <h2>Access Granted 🔓</h2>
          <p class="subtitle">You have successfully authenticated via Multi-Factor verification.</p>
          <div style="background: #f6f8fa; border: 1px solid #d0d7de; padding: 16px; border-radius: 6px; margin: 20px 0; font-size: 14px;">
            <p><strong>Username:</strong> <span id="dashUser">-</span></p>
            <p style="margin-top: 8px;"><strong>Account Tier:</strong> <span id="dashRole" style="background:#0066cc; color:#fff; padding:2px 6px; font-size:11px; border-radius:10px; text-transform:uppercase;">-</span></p>
          </div>
          <button onclick="handleLogout()" style="background:#24292f;">Sign Out Account</button>
        </div>
      </div>

      <script>
        const state = { errorBox: document.getElementById('errorBox'), successBox: document.getElementById('successBox') };

        function showMessage(type, text) {
          state.errorBox.style.display = type === 'error' ? 'block' : 'none';
          state.successBox.style.display = type === 'success' ? 'block' : 'none';
          if(type === 'error') state.errorBox.innerText = text;
          if(type === 'success') state.successBox.innerText = text;
        }

        function clearMessages() { showMessage('none'); }

        function switchView(viewId) {
          clearMessages();
          ['loginView', 'registerView', 'enrollView', 'mfaChallengeView', 'dashboardView'].forEach(id => {
            document.getElementById(id).classList.add('hidden');
          });
          document.getElementById(viewId + 'View').classList.remove('hidden');
        }

        async function handleRegister(e) {
          e.preventDefault();
          clearMessages();
          try {
            const res = await fetch('/api/register', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: document.getElementById('regUser').value, password: document.getElementById('regPass').value })
            });
            const data = await res.json();
            if (!res.ok) return showMessage('error', data.error || 'Registration rejected');
            
            document.getElementById('qrImage').src = data.qr;
            document.getElementById('secretKey').innerText = data.secret;
            document.getElementById('enrollPendingId').value = data.pendingId;
            switchView('enroll');
            showMessage('success', 'Account registered! Scan your QR code below to proceed.');
          } catch (err) { showMessage('error', 'Network failure communicating with engine.'); }
        }

        async function handle2FAActivate(e) {
          e.preventDefault();
          clearMessages();
          try {
            const res = await fetch('/api/2fa/activate', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ pendingId: document.getElementById('enrollPendingId').value, code: document.getElementById('enrollCode').value })
            });
            if (!res.ok) {
              const data = await res.json();
              return showMessage('error', data.error || 'Invalid 2FA token');
            }
            showMessage('success', '2FA Device verification complete! You can now log in.');
            switchView('login');
            document.getElementById('registerForm').reset();
            document.getElementById('enrollForm').reset();
          } catch (err) { showMessage('error', 'Network connection anomaly detected.'); }
        }

        async function handleLogin(e) {
          e.preventDefault();
          clearMessages();
          try {
            const res = await fetch('/api/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: document.getElementById('loginUser').value, password: document.getElementById('loginPass').value })
            });
            const data = await res.json();
            if (!res.ok) return showMessage('error', data.error || 'Authentication denied');
            
            if (data.step === '2fa') {
document.getElementById('challengePendingId').value = data.pendingId;
switchView('mfaChallenge');
} else if (data.step === 'enroll') {
document.getElementById('qrImage').src = data.qr;
document.getElementById('secretKey').innerText = data.secret;
document.getElementById('enrollPendingId').value = data.pendingId;
switchView('enroll');
showMessage('error', 'Multi-factor configuration required to activate account.');
}
} catch (err) { showMessage('error', 'Server offline or network trace broken.'); }
}
async function handle2FAVerify(e) {
e.preventDefault();
clearMessages();
try {
const res = await fetch('/api/2fa/verify', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ pendingId: document.getElementById('challengePendingId').value, code: document.getElementById('challengeCode').value })
});
const data = await res.json();
if (!res.ok) return showMessage('error', data.error || 'Invalid passcode match');
document.getElementById('dashUser').innerText = data.username;
document.getElementById('dashRole').innerText = data.role;
switchView('dashboard');
showMessage('success', 'Session cryptographically signed.');
} catch (err) { showMessage('error', 'Token resolution error.'); }
}
async function handleLogout() {
clearMessages();
try {
await fetch('/api/logout', { method: 'POST' });
document.getElementById('loginForm').reset();
document.getElementById('challengeForm').reset();
switchView('login');
showMessage('success', 'Logged out safely.');
} catch (err) { switchView('login'); }
}


`);
});


### ⚙️ Piece 6: API Back-End Endpoint Routes
This section processes request logic for accounts (Registration, Login Challenge, 2FA Device Bindings, Cookie Authentication Signing, and Logging out).

```javascript
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

app.post('/api/logout', (req, res) => {
  const sid = cookies(req).sid;
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));
