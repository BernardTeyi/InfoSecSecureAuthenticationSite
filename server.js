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

// ================= Input Sanitization & Validation =================
const cleanName = u => typeof u === 'string' ? u.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim() : u;
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPassword = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const GENERIC = { error: 'Invalid username or password' };
const dummy = C.hashPassword('dummy-password');

async function enrollPayload(user) {
  const uri = `otpauth://totp/SecureAuth:${encodeURIComponent(user.username)}?secret=${user.totpSecret}&issuer=SecureAuth&digits=6&period=30`;
  return { step: 'enroll', pendingId: newPending(user.id, 'enroll'), secret: user.totpSecret, qr: await QRCode.toDataURL(uri) };
}

// ================= Integrated Standalone Front-End UI =================
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

        <!-- 1. LOGIN SCREEN -->
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

        <!-- 2. REGISTRATION SCREEN -->
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

        <!-- 3. MFA ENROLLMENT SCREEN -->
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

        <!-- 4. SECOND-FACTOR CHALLENGE SCREEN -->
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

        <!-- 5. DASHBOARD VIEW -->
        <div id="dashboardView" class="hidden">
          <h2>Access Granted 🔓</h2>
          <p class="subtitle">You have successfully authenticated via Multi-Factor verification.</p>
          <div style="background: #f6f8fa; border: 1px solid #d0d7de; padding: 16px; border-radius: 6px; margin: 20px 0; font-size: 14px;">
            <p><strong>Username:</strong> <span id="dashUser">-</span></p>
