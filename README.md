# Multi-Project Email Gateway, OTP & Broadcast Service

A unified, self-hosted email API service designed for all your personal projects. Send One-Time Passwords (OTPs), password resets, greeting emails, and **broadcast messages** to remembered users with project-specific branding and subject tagging (e.g. `Reset Password - abc` and `Reset Password - xyz`).

Powered by **Flask**, **MongoDB Atlas**, and **SMTP** (supporting **Personal Gmail** initially and **Business Email / Google Workspace (`@dhyey.cc`)** in the future).

Deployable directly to **Vercel** or accessible behind **Cloudflare**.

---

## 🚀 Key Features

* **Per-Project API Keys:** Assign Key 1 to Project `abc` and Key 2 to Project `xyz`.
* **Automatic Subject Tagging:**
  * Project `abc` sends: `Reset Password - abc`
  * Project `xyz` sends: `Reset Password - xyz`
  * OTPs: `482910 is your verification code - abc`
* **Automated User Retention:** Automatically remembers recipient emails per project upon sending an OTP, verifying, or sending a greeting.
* **Targeted Broadcast System:**
  * **Per-Project Broadcast (`POST /api/broadcast`):** Send updates exclusively to users registered under project `xyz`.
  * **All-Projects Broadcast (`POST /api/broadcast/all`):** Global announcement dispatched across all projects with email deduplication.
* **One-Click Unsubscribe (RFC 8058 compliant) with Smart Retention:**
  * When a user unsubscribes, they are **kept in the database** with `isSubscribed: false`.
  * **Broadcasts are suppressed** for unsubscribed users, but **mandatory emails (OTPs, Password Resets) are always delivered**.
  * If an unsubscribed user interacts with the service again (requests an OTP, verifies a code, or requests a password reset), they are **automatically restored to a normal active subscriber**.
  * Native `List-Unsubscribe: One-Click` headers for Gmail & Yahoo inbox compliance.
  * Dedicated unsubscribe confirmation & re-subscribe web pages.
* **Customizable Headers & Footers:** Set project-wide logo, header titles, and footer legal notes, or override them dynamically per email.
* **Future-Proof SMTP Transport:**
  * **Today (Free):** Personal Gmail with a 16-character Google App Password.
  * **Tomorrow:** Google Workspace or custom business mail for `dhyey.cc` (e.g. `support@dhyey.cc`) simply by updating 3 environment variables.
* **Interactive Developer Playground:** Built-in web UI to test OTPs, broadcasts, subscribers, resets, and greetings live.

---

## 📁 Project Structure

```
personal-otp/
├── api/
│   └── index.py            # Flask API, multi-project auth, broadcasts, SMTP engine
├── public/
│   ├── index.html          # Interactive developer portal & test playground
│   ├── app.js              # Tab switcher, broadcast form, subscriber viewer
│   └── style.css           # Clean modern styles, dark/light mode responsive design
├── .env.example            # Environment variables configuration guide
├── requirements.txt        # Flask, PyMongo, dnspython
├── vercel.json             # Vercel serverless routing (/api/* -> /api/index)
└── README.md
```

---

## ⚙️ Configuration (`.env`)

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 1. Database (MongoDB Atlas)
```env
MONGODB_URI=mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=otp_service
```

### 2. Security & Keys
```env
MASTER_API_KEY=master_secret_change_me_12345
OTP_SECRET=random_32_byte_secret_string

# Pre-seeded project API keys (created automatically on startup)
PROJECT_ABC_KEY=sk_abc_dev123
PROJECT_XYZ_KEY=sk_xyz_dev123
```

### 3. SMTP Setup

#### Phase 1: Personal Gmail (Free)
1. Turn on 2-Step Verification in your Google Account.
2. Go to [Google App Passwords](https://myaccount.google.com/apppasswords) and create a password for "Mail".
3. Configure your `.env`:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your_personal_email@gmail.com
SMTP_PASSWORD=abcd efgh ijkl mnop
SMTP_FROM_EMAIL=your_personal_email@gmail.com
SMTP_FROM_NAME=Passcode
```

#### Phase 2: Upgrading to Business Email (`@dhyey.cc`)
When you purchase Google Workspace for `dhyey.cc`, create an App Password under your business account and update `.env`:
```env
SMTP_USER=support@dhyey.cc
SMTP_PASSWORD=your_google_workspace_app_password
SMTP_FROM_EMAIL=support@dhyey.cc
```

---

## 📡 API Reference

All requests must include your project's API key in the headers:
```http
X-API-Key: sk_abc_dev123
```
*(or `Authorization: Bearer sk_abc_dev123`)*

---

### 1. Broadcasts

#### A. Per-Project Broadcast (`POST /api/broadcast`)
Sends an announcement to all active subscribers registered to the calling project.
```json
{
  "subject": "New Release v2.0",
  "title": "Exciting updates for you!",
  "message": "<p>We've launched new features...</p>",
  "action_url": "https://yourapp.com/v2",
  "action_label": "Explore Updates",
  "custom_header": "Optional header title or HTML",
  "custom_footer": "Optional footer text"
}
```

#### B. All-Projects Broadcast (`POST /api/broadcast/all`)
Requires `MASTER_API_KEY`. Dispatches an announcement to every unique active user across all projects.
```json
{
  "subject": "Global Maintenance Notice",
  "title": "Scheduled Upgrades",
  "message": "<p>All services will undergo a brief 5-minute upgrade.</p>"
}
```

---

### 2. View Subscribers (`GET /api/subscribers`)
Returns all remembered users for the active project and their subscription status (`isSubscribed: true/false`).

---

### 3. Send OTP (`POST /api/send-otp`)
Generates a 6-digit code, remembers the user in `subscribers`, and delivers the email.
```json
{ "email": "user@example.com" }
```

---

### 4. Verify OTP (`POST /api/verify-otp`)
```json
{ "email": "user@example.com", "otp": "593812" }
```

---

### 5. Send Password Reset (`POST /api/send-reset-password`)
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "reset_url": "https://yourapp.com/reset?token=xyz",
  "expires_in_minutes": 15
}
```

---

### 6. Send Greeting / Welcome (`POST /api/send-greeting`)
```json
{
  "email": "user@example.com",
  "name": "Alex",
  "title": "Welcome aboard!",
  "message": "<p>We're glad to have you with us.</p>",
  "action_url": "https://yourapp.com/dashboard",
  "action_label": "Go to Dashboard"
}
```

---

### 7. Unsubscribe Endpoints
* `GET /api/unsubscribe?project=abc&email=user@example.com&sig=...` (One-click browser unsubscribe)
* `POST /api/unsubscribe` (JSON API)
* `GET /api/resubscribe?...` (Undo unsubscribe)

---

## 🚢 Deployment

### Deploying to Vercel
1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in this project directory.
3. In Vercel Project Dashboard (`Settings > Environment Variables`), add your environment variables.

### Custom Domain via Cloudflare (`dhyey.cc`)
1. In Vercel, add `otp.dhyey.cc` (or `api.dhyey.cc`).
2. In Cloudflare DNS for `dhyey.cc`, create a **CNAME** record:
   * **Name:** `otp`
   * **Target:** `cname.vercel-dns.com`
