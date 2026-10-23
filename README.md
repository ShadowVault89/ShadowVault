# SHADOW VAULT

Dark-themed marketplace website with a small local Node.js authentication backend.

## Run on Windows

1. Install Node.js LTS from https://nodejs.org/ if it is not already installed.
2. Extract this project folder.
3. Double-click `start.bat`, or open a terminal in this folder and run `npm start`.
4. Open **http://127.0.0.1:3000** in your browser.
5. Use **Create Account** to register, then Sign In on later visits. Stop the server with Ctrl+C.

Do not open `public/index.html` directly as a file; the authentication API only works through the local server.

## Included

- Responsive Shadow Vault catalog and product detail popups.
- Search across product listings.
- Create Account and Sign In forms.
- Passwords are stored as salted scrypt hashes, not as plain text.
- HttpOnly, SameSite session cookie; logout support.
- Local user records stored in `data/users.json` (created automatically).

## Important security limits

This is a starter project for **local testing**, not a production-ready public account system. Sessions are held in server memory and are cleared when the server restarts. There is no email verification, password reset, rate limiting, CAPTCHA, database service, or payment processing. Before putting it on the public internet, use HTTPS and a maintained authentication provider or have the backend professionally hardened. Never reuse a password from another site.

Only list accounts/services you are authorized to transfer and that comply with each platform's rules. Do not request passwords or recovery codes in public Discord tickets.

Discord: https://discord.gg/3ZK7JYZhx
