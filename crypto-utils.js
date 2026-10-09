'use strict';
// All cryptography lives here so it is easy to review.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- Secrets (.env) ----------
// PEPPER : secret mixed into every password hash. Kept OUT of the database.
// DB_KEY : AES-256 key that encrypts the database and signs backups.
function loadSecrets() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) {
    const body = `PEPPER=${crypto.randomBytes(32).toString('hex')}\nDB_KEY=${crypto.randomBytes(32).toString('hex')}\n`;
    fs.writeFileSync(file, body, { mode: 0o600 });
    console.log('[setup] Generated .env with new PEPPER and DB_KEY. Store a copy somewhere safe, separate from the backups.');
  }
  const env = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.+)\s*$/);
    if (m) env[m[1]] = m[2];
  }
  if (!env.PEPPER || !/^[0-9a-f]{64}$/.test(env.DB_KEY || '')) throw new Error('.env is missing PEPPER or has an invalid DB_KEY');
  return { PEPPER: env.PEPPER, DB_KEY: Buffer.from(env.DB_KEY, 'hex') };
}
const { PEPPER, DB_KEY } = loadSecrets();

// ---------- Password hashing: salt + pepper + scrypt ----------
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
function hashPassword(password, saltHex = crypto.randomBytes(16).toString('hex')) {
  // 1) pepper: HMAC the password with the secret pepper
  const peppered = crypto.createHmac('sha256', PEPPER).update(password).digest();
  // 2) salt + slow KDF: unique per user, defeats rainbow tables and slows brute force
  const hash = crypto.scryptSync(peppered, Buffer.from(saltHex, 'hex'), 64, SCRYPT).toString('hex');
  return { salt: saltHex, hash };
}
function verifyPassword(password, salt, expectedHash) {
  return safeEq(hashPassword(password, salt).hash, expectedHash);
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const token = (n = 32) => crypto.randomBytes(n).toString('hex');

// ---------- Confidentiality + integrity: AES-256-GCM ----------
// GCM encrypts AND authenticates. Any change to the file makes decryption fail.
const AAD = Buffer.from('secure-auth-db-v1');
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', DB_KEY, iv);
  c.setAAD(AAD);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decrypt(b64) {
  const raw = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', DB_KEY, raw.subarray(0, 12));
  d.setAAD(AAD);
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
}
// HMAC used to sign backup files (detects tampering of the backup itself)
const mac = (buf) => crypto.createHmac('sha256', DB_KEY).update(buf).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- TOTP (RFC 6238, works with Google/Microsoft Authenticator, Authy) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = ((val << 8) | b) & 0xffff; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function b32dec(s) {
  let bits = 0, val = 0; const out = [];
  for (const ch of s) { const i = B32.indexOf(ch); if (i < 0) continue; val = ((val << 5) | i) & 0xffff; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
const newTotpSecret = () => b32enc(crypto.randomBytes(20));
function hotp(secretB32, counter) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32dec(secretB32)).update(buf).digest();
  const o = h[19] & 15;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
  return String(n).padStart(6, '0');
}
// Returns the matched time-step (so the caller can block code replay) or null.
function checkTotp(secretB32, code, lastStep = 0) {
  if (!/^\d{6}$/.test(String(code))) return null;
  const now = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) {
    const step = now + d;
    if (step > lastStep && safeEq(hotp(secretB32, step), code)) return step;
  }
  return null;
}

module.exports = { hashPassword, verifyPassword, safeEq, token, encrypt, decrypt, mac, sha256, newTotpSecret, checkTotp, hotp };
