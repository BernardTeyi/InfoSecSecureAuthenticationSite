'use strict';
const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
app.use(express.json());

// --- HARDENED CONFIGURATION (Pepper, Confidentality, & Integrity Keys) ---
const STATIC_PEPPER = process.env.STATIC_PEPPER || '3f8a9c2e1b7d4e5f6a0b9c8d7e6f5a4b';
const BACKUP_MAC_SECRET = process.env.BACKUP_MAC_SECRET || 'tamper-proof-backup-signature-key-9988';
const DB_ENC_KEY = process.env.DB_ENC_KEY 
  ? crypto.scryptSync(process.env.DB_ENC_KEY, 'system-salt', 32) 
  : crypto.randomBytes(32);

// Databases & Trackers (Volatile transient array store for Serverless nodes)
let users = [];
const activeSessions = new Map();
const backupsStore = [];

// --- HELPER CRYPTO MECHANISMS ---
const hashPasswordWithPepper = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const combined = password + salt + STATIC_PEPPER;
  const hash = crypto.pbkdf2Sync(combined, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
};

const makeBase32Secret = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  for (let i = 0; i < 16; i++) result += chars[Math.floor(Math.random() * chars.length)];
  return result;
};

const verify2FA = (secret, code) => {
  if (!code || code.length !== 6) return false;
  const computedStep = Math.floor(Date.now() / 30000);
  
  const base32Decode = (str) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const buf = Buffer.alloc(Math.ceil(str.length * 5 / 8));
    let bits = 0, value = 0, idx = 0;
    for (let i = 0; i < str.length; i++) {
      const val = chars.indexOf(str[i].toUpperCase());
      if (val === -1) continue;
      value = (value << 5) | val; bits += 5;
      if (bits >= 8) { buf[idx++] = (value >> (bits - 8)) & 255; bits -= 8; }
    }
    return buf.subarray(0, idx);
  };

  for (let window = -1; window <= 1; window++) {
    const step = computedStep + window;
    const stepBuffer = Buffer.alloc(8);
    stepBuffer.writeUInt32BE(step, 4);
    const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(stepBuffer).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const codeInt = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    if (String(codeInt).padStart(6, '0') === code) return true;
  }
  return false;
};

// --- AUTOBACKUP GENERATION ENGINE (Confidentiality & Integrity) ---
function triggerAutomatedCryptographicBackup() {
  try {
    const rawDataStr = JSON.stringify({ users });
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', DB_ENC_KEY, iv);
    let encrypted = cipher.update(rawDataStr, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const ciphertext = iv.toString('hex') + ':' + encrypted;

    const hmacSignature = crypto.createHmac('sha256', BACKUP_MAC_SECRET)
      .update(ciphertext)
      .digest('hex');

    backupsStore.unshift({
      timestamp: new Date().toISOString(),
      payload: ciphertext,
      mac: hmacSignature
    });

    if (backupsStore.length > 5) backupsStore.pop();
    console.log('[Autobackup] Secure encrypted state generated successfully.');
  } catch (err) {
    console.error('Backup pipeline error:', err.message);
  }
}

// ================= 1. THE FRONTEND INTERFACE =================
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Secure Multi-Factor Portal</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Roboto, sans-serif; }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .card { background: rgba(255, 255, 255, 0.98); padding: 35px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 100%; max-width: 500px; transition: all 0.3s ease; }
        h2 { color: #0f172a; margin-bottom: 8px; font-size: 26px; font-weight: 700; text-align: center; }
        .info-text { font-size: 13px; color: #475569; background: #f1f5f9; padding: 10px 14px; border-radius: 8px; border-left: 4px solid #0284c7; margin-bottom: 20px; line-height: 1.5; text-align: left; }
        .step-badge { display: inline-block; background: #e0f2fe; color: #0369a1; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 12px; margin-bottom: 12px; text-transform: uppercase; }
        input { width: 100%; padding: 12px 14px; margin: 8px 0 18px 0; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 15px; outline: none; transition: all 0.2s; }
        input:focus { border-color: #0284c7; box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15); }
        button { width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        button:hover { background: #0369a1; transform: translateY(-1px); }
        .nav-container { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; padding-top: 15px; border-top: 1px solid #e2e8f0; }
        .btn-link { color: #0284c7; background: none; border: none; font-size: 14px; font-weight: 600; cursor: pointer; width: auto; padding: 0; }
        .btn-link:hover { color: #0369a1; text-decoration: underline; transform: none; }
        .error-msg { background: #fef2f2; border: 1px solid #fca5a5; color: #b91c1c; padding: 12px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; display: none; text-align: left; }
        .success-msg { background: #f0fdf4; border: 1px solid #86efac; color: #15803d; padding: 12px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; display: none; text-align: left; }
        .qr-wrapper { text-align: center; margin: 15px 0; background: #fff; padding: 15px; border-radius: 12px; border: 1px solid #e2e8f0; }
        .qr-wrapper img { max-width: 160px; }
        .secret-tag { display: block; font-family: monospace; background: #f8fafc; border: 1px solid #cbd5e1; padding: 6px; border-radius: 4px; font-size: 14px; margin-top: 8px; word-break: break-all; color: #334155; }
        .role-badge { display: inline-block; background: #4f46e5; color: white; padding: 2px 8px; font-size: 11px; border-radius: 12px; text-transform: uppercase; font-weight: bold; }
        .admin-panel { margin-top: 25px; padding-top: 20px; border-top: 2px dashed #cbd5e1; text-align: left; }
        .user-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        .user-table th, .user-table td { padding: 8px; border: 1px solid #cbd5e1; text-align: left; }
        .user-table th { background: #f8fafc; font-weight: 600; }
        .btn-action { padding: 4px 8px; font-size: 11px; border-radius: 4px; cursor: pointer; border: none; margin-right: 4px; width: auto; display: inline-block; }
        .btn-del { background: #ef4444; color: white; }
        .btn-del:hover { background: #dc2626; }
        .btn-role { background: #64748b; color: white; }
        .btn-role:hover { background: #475569; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <div id="alertError" class="error-msg"></div>
        <div id="alertSuccess" class="success-msg"></div>

        <!-- VIEW 1: LOGIN -->
        <div id="viewLogin">
          <span class="step-badge">Step 1 of 2</span>
          <h2>Sign In</h2>
          <div class="info-text"><b>Instructions:</b> Enter your credentials below. Our system applies standard Salt and Pepper hashing configurations to verify core confidentiality profiles safely.</div>
          <input type="text" id="logUser" placeholder="Enter Username">
          <input type="password" id="logPass" placeholder="Enter Password">
          <button onclick="submitLoginStep1()">Next: 2FA Challenge →</button>
          <div class="nav-container">
            <span>New here?</span>
            <button class="btn-link" onclick="navigate('Register')">Create a secure profile</button>
          </div>
        </div>

        <!-- VIEW 2: REGISTER -->
        <div id="viewRegister">
          <span class="step-badge">Profile Setup</span>
          <h2>Create Account</h2>
          <div class="info-text"><b>Next Steps:</b> Pick a username and strong password. Upon validation, the system will output a unique cryptographic binding payload for your MFA authenticator app.</div>
          <input type="text" id="regUser" placeholder="Username (3-20 characters)">
          <input type="password" id="regPass" placeholder="Password (Min. 10 characters)">
          <button onclick="submitRegistration()">Generate Cryptographic Bindings</button>
          <div class="nav-container">
            <button class="btn-link" onclick="navigate('Login')">← Back to Login</button>
          </div>
        </div>

        <!-- VIEW 3: MFA CHALLENGE / ENROLL -->
        <div id="viewMfa" class="hidden">
          <span class="step-badge" id="mfaStepHeader">Identity Verification</span>
          <h2>MFA Verification</h2>
          <div class="info-text" id="mfaInstructions">Provide the dynamic time-based verification pin generated by your linked device container to complete the session pipeline.</div>
          <div id="qrWrapper" class="hidden">
            <div class="qr-wrapper">
              <img id="qrImgElement" src="" alt="MFA Token Setup">
              <span class="secret-tag">Manual Entry Key: <b id="textSecretElement"></b></span>
            </div>
          </div>
          <input type="text" id="mfaCodeField" placeholder="Enter 6-digit pin code" maxlength="6">
          <button onclick="submitMfaVerification()">Complete Secure Verification Match</button>
          <div class="nav-container">
            <button class="btn-link" onclick="abortMfa()">← Restart Authentication Flow</button>
          </div>
        </div>

let currentTargetUser = '';
let mfaEnrollmentMode = false;
function navigate(viewName) {
hideAlerts();
document.getElementById('viewLogin').classList.toggle('hidden', viewName !== 'Login');
document.getElementById('viewRegister').classList.toggle('hidden', viewName !== 'Register');
document.getElementById('viewMfa').classList.toggle('hidden', viewName !== 'Mfa');
document.getElementById('viewDash').classList.toggle('hidden', viewName !== 'Dash');
}
function showAlert(isError, text) {
const el = document.getElementById(isError ? 'alertError' : 'alertSuccess');
el.innerText = text; el.style.display = 'block';
}
function hideAlerts() {
document.getElementById('alertError').style.display = 'none';
document.getElementById('alertSuccess').style.display = 'none';
}
async function submitRegistration() {
hideAlerts();
const user = document.getElementById('regUser').value;
const pass = document.getElementById('regPass').value;
const res = await fetch('/api/register', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({user, pass})
});
const data = await res.json();
if (!res.ok) return showAlert(true, data.error);
currentTargetUser = user;
mfaEnrollmentMode = true;
document.getElementById('mfaStepHeader').innerText = "Device Link Setup";
document.getElementById('mfaInstructions').innerText = "Scan the QR structure with Google Authenticator or insert the manual key string before inserting your 6-digit synchronization code confirmation.";
document.getElementById('qrImgElement').src = data.qr;
document.getElementById('textSecretElement').innerText = data.secret;
document.getElementById('qrWrapper').classList.remove('hidden');
navigate('Mfa');
showAlert(false, 'Cryptographic credentials generated. Please link your token provider.');
}
async function submitLoginStep1() {
hideAlerts();
const user = document.getElementById('logUser').value;
const pass = document.getElementById('logPass').value;
const res = await fetch('/api/login-step1', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({user, pass})
});
const data = await res.json();
if (!res.ok) return showAlert(true, data.error);
currentTargetUser = user;
mfaEnrollmentMode = false;
document.getElementById('mfaStepHeader').innerText = "Step 2 of 2";
document.getElementById('mfaInstructions').innerText = "Enter the moving 6-digit factor passcode active inside your device app to confirm authorization matching tokens.";
document.getElementById('qrWrapper').classList.add('hidden');
navigate('Mfa');
}
async function submitMfaVerification() {
hideAlerts();
const code = document.getElementById('mfaCodeField').value;
const endpoint = mfaEnrollmentMode ? '/api/register-step2' : '/api/login-step2';
const res = await fetch(endpoint, {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({user: currentTargetUser, code})
});
const data = await res.json();
if (!res.ok) return showAlert(true, data.error);
document.getElementById('dashLabelUser').innerText = data.username;
document.getElementById('dashLabelRole').innerText = data.role;
if (data.role === 'admin') {
document.getElementById('adminPanelWrapper').classList.remove('hidden');
renderUserManagementConsole(data.allUsers);
} else {
document.getElementById('adminPanelWrapper').classList.add('hidden');
}
navigate('Dash');
showAlert(false, 'MFA Handshake success. Access authorized.');
document.getElementById('mfaCodeField').value = '';
}
function renderUserManagementConsole(usersList) {
const tbody = document.getElementById('userTableBody');
tbody.innerHTML = '';
usersList.forEach(u => {
const tr = document.createElement('tr');
tr.innerHTML = `
${u.username}
${u.role}
`;
tbody.appendChild(tr);
});
}
async function modifyUserRole(username, currentRole) {
const nextRole = currentRole === 'admin' ? 'user' : 'admin';
const res = await fetch('/api/admin/change-role', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({ adminUser: currentTargetUser, targetUser: username, newRole: nextRole })
});
const data = await res.json();
if (!res.ok) return showAlert(true, data.error);
renderUserManagementConsole(data.allUsers);
showAlert(false, 'User privileges updated securely.');
}
async function deleteUserRecord(username) {
if (!confirm(`Confirm permanent extraction erasure of user account index "${username}"?`)) return;
const res = await fetch('/api/admin/delete-user', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({ adminUser: currentTargetUser, targetUser: username })
});
const data = await res.json();
if (!res.ok) return showAlert(true, data.error);
renderUserManagementConsole(data.allUsers);
showAlert(false, 'User record deleted from configuration parameters.');
}
function abortMfa() {
document.getElementById('logPass').value = '';
navigate('Login');
}



`);
});
// ================= 2. THE HARDENED REST ENDPOINTS =================
// Registration Pipeline Initialization
app.post('/api/register', async (req, res) => {
const { user, pass } = req.body;
if (!user || user.length < 3 || user.length > 20 || !/^[A-Za-z0-9_]+$/.test(user)) {
return res.status(400).json({ error: 'Username must be 3-20 alphanumeric characters or underscores.' });
}
if (!pass || pass.length < 10) {
return res.status(400).json({ error: 'Confidentiality requirements failed: Passwords require 10+ characters.' });
}
if (users.find(u => u.username === user.toLowerCase())) {
return res.status(409).json({ error: 'Data collision exception: Username already exists.' });
}
const secret = makeBase32Secret();
const uri = otpauth://totp/SecurePortal:${user}?secret=${secret}&issuer=SecurePortal;
const qrDataUrl = await QRCode.toDataURL(uri);
// Store credentials parameters in execution staging map memory
activeSessions.set(user.toLowerCase(), { password: pass, secret });
res.json({ secret, qr: qrDataUrl });
});
// Registration Finalization - Bound & Execute Initial Automatic Integrity Backup
app.post('/api/register-step2', (req, res) => {
const { user, code } = req.body;
const session = activeSessions.get(user.toLowerCase());
if (!session) return res.status(400).json({ error: 'Staging channel context missing. Re-verify credentials.' });
if (!verify2FA(session.secret, code)) {
return res.status(401).json({ error: 'Cryptographic challenge verification failed. Check device tokens.' });
}
// Salt + Pepper generation processing implementation layer
const cryptoCreds = hashPasswordWithPepper(session.password);
// Rule matrix layout definition: First profile registered on node becomes admin
const assignedRole = users.length === 0 ? 'admin' : 'user';
users.push({
username: user.toLowerCase(),
salt: cryptoCreds.salt,
hash: cryptoCreds.hash,
secret: session.secret,
role: assignedRole
});
activeSessions.delete(user.toLowerCase());
triggerAutomatedCryptographicBackup(); // Automated state snapshot validation trigger
res.json({ success: true, username: user.toLowerCase(), role: assignedRole, allUsers: users });
});
// Login Identity Check
app.post('/api/login-step1', (req, res) => {
const { user, pass } = req.body;
const matchedUser = users.find(u => u.username === user.toLowerCase());
if (!matchedUser) return res.status(401).json({ error: 'Access denied: Invalid profile parameters.' });
// Verification process recalculating Salt + Pepper parameters
const verifyHash = hashPasswordWithPepper(pass, matchedUser.salt).hash;
if (verifyHash !== matchedUser.hash) {
return res.status(401).json({ error: 'Access denied: Invalid profile parameters.' });
}
res.json({ nextStep: '2fa' });
});
// Login Handshake Token Completion Verification
app.post('/api/login-step2', (req, res) => {
const { user, code } = req.body;
const matchedUser = users.find(u => u.username === user.toLowerCase());
if (!matchedUser) return res.status(401).json({ error: 'Session execution exception.' });
if (!verify2FA(matchedUser.secret, code)) {
return res.status(401).json({ error: 'Multi-factor token matching failed.' });
}
res.json({
success: true,
username: matchedUser.username,
role: matchedUser.role,
allUsers: users
});
});
// ================= 3. AUTHORIZED ADMIN ROLE AREA =================
// Admin Role Elevation Toggle Route
app.post('/api/admin/change-role', (req, res) => {
const { adminUser, targetUser, newRole } = req.body;
const actor = users.find(u => u.username === adminUser.toLowerCase());
// Strict check role verification authorization policy
if (!actor || actor.role !== 'admin') {
return res.status(403).json({ error: 'Access Denied: Admin authorization clearance required.' });
}
const userRecord = users.find(u => u.username === targetUser.toLowerCase());
if (userRecord) {
userRecord.role = newRole;
triggerAutomatedCryptographicBackup();
}
res.json({ success: true, allUsers: users });
});
// Admin User Records Removal Action
app.post('/api/admin/delete-user', (req, res) => {
const { adminUser, targetUser } = req.body;
const actor = users.find(u => u.username === adminUser.toLowerCase());
if (!actor || actor.role !== 'admin') {
return res.status(403).json({ error: 'Access Denied: Admin authorization clearance required.' });
}
if (adminUser.toLowerCase() === targetUser.toLowerCase()) {
return res.status(400).json({ error: 'Operation rejected: Cannot extract your own active configuration.' });
}
users = users.filter(u => u.username !== targetUser.toLowerCase());
triggerAutomatedCryptographicBackup();
res.json({ success: true, allUsers: users });
});
const PORT_NUM = process.env.PORT || 3000;
app.listen(PORT_NUM, () => console.log(Server running on port ${PORT_NUM}));