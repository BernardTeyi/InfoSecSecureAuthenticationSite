'use strict';
// node restore.js            -> verify every backup (signature + decryption)
// node restore.js <file.enc> -> verify that backup, then restore it as the live DB
const fs = require('fs'), path = require('path');
const C = require('./crypto-utils');
const dir = path.join(__dirname, 'data', 'backups');
function verify(file) {
  try {
    const buf = fs.readFileSync(file);
    const sig = fs.readFileSync(file + '.mac', 'utf8').trim();
    if (!C.safeEq(C.mac(buf), sig)) return 'BAD SIGNATURE (file was modified)';
    JSON.parse(C.decrypt(buf.toString('utf8')));
    return 'OK';
  } catch { return 'CORRUPT (cannot decrypt)'; }
}
const arg = process.argv[2];
if (!arg) {
  for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.enc')).sort()) console.log(f.padEnd(40), verify(path.join(dir, f)));
} else {
  const file = path.isAbsolute(arg) ? arg : path.join(dir, path.basename(arg));
  const r = verify(file);
  if (r !== 'OK') { console.error('Refusing to restore:', r); process.exit(1); }
  fs.copyFileSync(file, path.join(__dirname, 'data', 'db.enc'));
  console.log('Restored', path.basename(file), '- restart the server.');
}
