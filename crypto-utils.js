const fs = require('fs');
const crypto = require('crypto');

function loadSecrets() {
  // If variables are already provided by Vercel, use them directly
  if (process.env.ENCRYPTION_KEY) {
    return {
      encryptionKey: Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
      jwtSecret: process.env.JWT_SECRET || 'fallback-secret'
    };
  }

  const envPath = '.env';
  
  // Local fallback: safely attempt to read or create the file on your computer
  try {
    if (!fs.existsSync(envPath)) {
      const eKey = crypto.randomBytes(32).toString('hex');
      const jSecret = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(envPath, `ENCRYPTION_KEY=${eKey}\nJWT_SECRET=${jSecret}\n`);
    }
    
    const envContent = fs.readFileSync(envPath, 'utf8');
    const eKey = envContent.match(/ENCRYPTION_KEY=(.*)/)?.[1];
    const jSecret = envContent.match(/JWT_SECRET=(.*)/)?.[1];
    
    return {
      encryptionKey: Buffer.from(eKey, 'hex'),
      jwtSecret: jSecret
    };
  } catch (error) {
    // If Vercel hits this, log it gracefully instead of throwing a 500 crash
    console.warn("Running in read-only environment. Ensure Vercel Environment Variables are set.");
    return {
      encryptionKey: crypto.randomBytes(32),
      jwtSecret: 'backup-secret-key'
    };
  }
}

const secrets = loadSecrets();

module.exports = {
  encrypt: (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', secrets.encryptionKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  },
  decrypt: (text) => {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', secrets.encryptionKey, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  },
  jwtSecret: secrets.jwtSecret
};
