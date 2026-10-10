'use strict';
const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
app.use(express.json());

const users = [];
const activeSessions = new Map();

const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
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
  const step = Math.floor(Date.now() / 30000);
  
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

  const stepBuffer = Buffer.alloc(8);
  stepBuffer.writeUInt32BE(step, 4);
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(stepBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const expectedCode = String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
  
  return expectedCode === code;
};

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Simple MFA Portal</title>
      <style>
        body { font-family: sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin:0; }
        .box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 350px; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .link { color: #0066cc; cursor: pointer; margin-top: 15px; display: inline-block; font-size: 14px; }
        .error { color: red; margin-bottom: 10px; display: none; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <div class="box">
        <div id="errMsg" class="error"></div>
        <div id="loginView">
          <h2>Sign In</h2>
          <input type="text" id="loginUser" placeholder="Username">
          <input type="password" id="loginPass" placeholder="Password">
          <button onclick="loginStep1()">Next</button>
          <div class="link" onclick="toggleView(false)">Create an account</div>
        </div>
        <div id="registerView" class="hidden">
          <h2>Create Account</h2>
          <input type="text" id="regUser" placeholder="Username (3-20 chars)">
          <input type="password" id="regPass" placeholder="Password (Min. 10 chars)">
          <button onclick="register()">Register</button>
          <div class="link" onclick="toggleView(true)">Back to Sign In</div>
        </div>
        <div id="mfaView" class="hidden">
          <h2>Enter 2FA Code</h2>
          <p id="mfaNote" style="font-size: 13px; color: #666;"></p>
          <div id="qrContainer" class="hidden">
            <img id="qrImg" src="" style="width: 150px; margin: 10px 0;"><br>
            <small>Secret: <b id="secretText"></b></small>
          </div>
          <input type="text" id="mfaCode" placeholder="6-digit code" maxlength="6">
          <button onclick="verifyMfaCode()">Verify & Login</button>
        </div>
        <div id="dashView" class="hidden">
          <h2>Access Granted! 🎉</h2>
          <p>Logged in as: <b id="dashUser"></b></p>
          <button onclick="location.reload()" style="background: #333;">Logout</button>
        </div>
      </div>
      <script>
        let currentUsername = '';
        let isRegisteringMfa = false;
        function toggleView(showLogin) {
          document.getElementById('errMsg').style.display = 'none';
          document.getElementById('loginView').classList.toggle('hidden', !showLogin);
          document.getElementById('registerView').classList.toggle('hidden', showLogin);
        }
        async function register() {
          const user = document.getElementById('regUser').value;
          const pass = document.getElementById('regPass').value;
          const res = await fetch('/api/register', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user, pass}) });
          const data = await res.json();
          if (!res.ok) return showError(data.error);
          currentUsername = user;
          isRegisteringMfa = true;
          document.getElementById('mfaNote').innerText = "Scan this QR code with Google Authenticator before entering the code:";
          document.getElementById('qrImg').src = data.qr;
          document.getElementById('secretText').innerText = data.secret;
          document.getElementById('qrContainer').classList.remove('hidden');
          document.getElementById('registerView').classList.add('hidden');
          document.getElementById('mfaView').classList.remove('hidden');
        }
        async function loginStep1() {
          const user = document.getElementById('loginUser').value;
          const pass = document.getElementById('loginPass').value;
          const res = await fetch('/api/login-step1', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user, pass}) });
          const data = await res.json();
          if (!res.ok) return showError(data.error);
          currentUsername = user;
          isRegisteringMfa = false;
          document.getElementById('mfaNote').innerText = "Enter the 6-digit code from your Authenticator app:";
          document.getElementById('qrContainer').classList.add('hidden');
          document.getElementById('loginView').classList.add('hidden');
          document.getElementById('mfaView').classList.remove('hidden');
        }
        async function verifyMfaCode() {
          const code = document.getElementById('mfaCode').value;
          const endpoint = isRegisteringMfa ? '/api/register-step2' : '/api/login-step2';
          const res = await fetch(endpoint, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user: currentUsername, code}) });
          const data = await res.json();
          if (!res.ok) return showError(data.error);
          document.getElementById('dashUser').innerText = currentUsername;
          document.getElementById('mfaView').classList.add('hidden');
          document.getElementById('dashView').classList.remove('hidden');
          document.getElementById('errMsg').style.display = 'none';
        }
        function showError(txt) {
          const err = document.getElementById('errMsg');
          err.innerText = txt;
          err.style.display = 'block';
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/api/register', async (req, res) => {
  const { user, pass } = req.body;
  if (!user || user.length < 3 || user.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters.' });
  if (!pass || pass.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  if (users.find(u => u.username === user.toLowerCase())) return res.status(409).json({ error: 'Username taken.' });

  const secret = makeBase32Secret();
  const uri = `otpauth://totp/SimpleAuth:${user}?secret=${secret}&issuer=SimpleAuth`;
  const qrDataUrl = await QRCode.toDataURL(uri);

  activeSessions.set(user.toLowerCase(), { password: pass, secret });
  res.json({ secret, qr: qrDataUrl });
});

app.post('/api/register-step2', (req, res) => {
  const { user, code } = req.body;
  const session = activeSessions.get(user.toLowerCase());
  if (!session) return res.status(400).json({ error: 'Session expired.' });

  if (!verify2FA(session.secret, code)) return res.status(401).json({ error: 'Invalid 2FA code.' });

  const cryptoCreds = hashPassword(session.password);
  users.push({ username: user.toLowerCase(), salt: cryptoCreds.salt, hash: cryptoCreds.hash, secret: session.secret });
  activeSessions.delete(user.toLowerCase());
  res.json({ success: true });
});

app.post('/api/login-step1', (req, res) => {
  const { user, pass } = req.body;
  const matchedUser = users.find(u => u.username === user.toLowerCase());
  if (!matchedUser) return res.status(401).json({ error: 'Invalid username or password.' });

  const checkHash = hashPassword(pass, matchedUser.salt).hash;
  if (checkHash !== matchedUser.hash) return res.status(401).json({ error: 'Invalid username or password.' });

  res.json({ nextStep: '2fa' });
});

app.post('/api/login-step2', (req, res) => {
  const { user, code } = req.body;
  const matchedUser = users.find(u => u.username === user.toLowerCase());
  if (!matchedUser) return res.status(401).json({ error: 'Session error.' });

  if (!verify2FA(matchedUser.secret, code)) return res.status(401).json({ error: 'Invalid 2FA code.' });

  res.json({ success: true });
});

const PORT_NUM = process.env.PORT || 3000;
app.listen(PORT_NUM, () => console.log(`Server running on port ${PORT_NUM}`));
