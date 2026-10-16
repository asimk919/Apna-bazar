# Apna Bazaar — Termux multi-seller marketplace starter

Includes:
- Node.js + Express server
- SQLite database for accounts, products, orders and payment events
- Hashed passwords, HTTP-only sessions, CSRF tokens, rate-limited login/register
- Customer and seller registration/login
- Seller-only product upload/edit/delete ownership checks
- JPG/PNG/WEBP uploads limited to 3 MB
- 50 seeded sample products
- Cart, checkout, order history and seller order management
- COD order creation
- Card/JazzCash/Easypaisa methods shown as not configured until a real gateway is integrated

## Run on Termux

```bash
pkg update && pkg upgrade -y
pkg install nodejs-lts python make clang -y
cd ~/daraz_style_marketplace
npm install
npm run seed
npm start
```

Open on the same phone: `http://127.0.0.1:3000`

If `nodejs-lts` is unavailable, use `pkg install nodejs -y`.

## Demo seller account

- Email: `demo.seller@example.com`
- Password: `ChangeMe123!`

Change/remove this demo account before any deployment. For a real public marketplace, set up admin controls, verified email/phone, password reset, backups, logging, HTTPS, abuse protection, image moderation and a production-grade session secret.

## Database and uploaded images

- SQLite: `data/marketplace.sqlite`
- Session store: `data/sessions.sqlite`
- Product images: `uploads/`

Back up these directories before updates.

## Security and payment limitations

This is a local starter, not a production-audited marketplace. Do not expose it to the public internet as-is. The default local host is `127.0.0.1`; this prevents other devices from connecting by default. A production deployment needs HTTPS and a secret supplied through the `SESSION_SECRET` environment variable.

COD is the only enabled order payment method. Card, JazzCash and Easypaisa require merchant onboarding and their current official integration specifications. The app intentionally rejects online checkouts until a verified server-side payment flow is implemented. Never collect/store raw card numbers, CVV, wallet PINs or OTPs in this app.

## Android APK

This project is currently a mobile-friendly web app. To make a standalone APK, wrap the hosted app with a maintained Android WebView/Capacitor project and build it using Android SDK tooling. The local Termux server must be running for the localhost version; a standalone APK or public multi-seller service needs a separately hosted backend or packaged backend design.
