# Secure Auth

Simple login system: identification, TOTP two-factor, role-based access, salted + peppered passwords, encrypted database, automatic signed backups.

## Run
    npm install
    npm start          # http://localhost:3000
On first start a `.env` file is created with a random PEPPER and DB_KEY. Keep a copy somewhere safe, away from the backups. If DB_KEY is lost, the data cannot be recovered.

## How each requirement is met
| Requirement | Where | How |
|---|---|---|
| 1. Identification | server.js `/api/register`, `/api/login` | Unique username, strong-password rules, generic error messages, lockout after 5 failed attempts |
| 2. Two-factor | crypto-utils.js `checkTotp` | TOTP (RFC 6238) with an authenticator app. Mandatory: login is incomplete without the code. Used codes cannot be replayed |
| 3. Authorization | server.js `requireRole` | Two roles, `user` and `admin`. The first account registered becomes admin. Admin can change roles, delete users, view the audit log and trigger a backup |
| 4. Salt + pepper | crypto-utils.js `hashPassword` | Password -> HMAC-SHA256 with secret pepper (stored in .env, not in the DB) -> scrypt with a unique 16-byte salt per user |
| Confidentiality | crypto-utils.js `encrypt` | Whole database encrypted with AES-256-GCM |
| Integrity | `decrypt`, `mac`, audit chain | GCM auth tag detects any change to the DB. Backups carry an HMAC signature. The audit log is a SHA-256 hash chain, so edits or deletions are detectable |
| Auto-backup | server.js `backup` | On start, every `BACKUP_MINUTES` (default 60) if data changed, and on shutdown. Last 10 kept |

## Interface
A colourful single-page UI with a navigation bar, step indicators for sign-up and login, and short "what's happening / next step" hints on every screen. Pages:
- **Login, Register, 2FA setup, 2FA code**: guided flow with a live password-strength checklist and a 30-second code countdown
- **Dashboard**: role badge, shortcut tiles, and live user stats for admins
- **My account**: profile, 2FA status, change password (signs out other devices)
- **Users** (admin): change roles, unlock locked accounts, reset 2FA, delete users, search, and a role-permission table
- **Audit and backups** (admin): hash-chain verification banner, recent events, one-click backup

## Role rules
- Two roles: `user` and `admin`. The first account created becomes admin.
- Role changes apply immediately, with no re-login needed. Deleting a user or resetting their 2FA ends their sessions.
- An admin cannot change, delete or reset the 2FA of their own account, so at least one admin always remains.
- Every action is enforced on the server. Hiding buttons in the UI is only for convenience.

## Backups
    npm run restore                    # verify all backups
    node restore.js db-<timestamp>.enc # verify, then restore one

## Before real deployment
Run behind HTTPS with `NODE_ENV=production`, add IP-based rate limiting, and move sessions to a persistent store.
