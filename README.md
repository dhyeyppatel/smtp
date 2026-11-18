# Multi-Project Email Gateway, OTP & Broadcast Service

A unified, self-hosted email API service designed for all your personal and team projects. Send One-Time Passwords (OTPs), password resets, greeting emails, and **rate-limited broadcasts** to remembered users with project-specific branding, per-project `Reply-To` routing, and **Bring-Your-Own-SMTP (BYOS)** support.

Powered by **Flask**, **MongoDB Atlas**, and **SMTP** (supporting **Personal Gmail** initially and **Google Workspace (`@dhyey.cc`)** or any custom SMTP server).

Deployable directly to **Vercel** or accessible behind **Cloudflare**.

---

## 🚀 Key Architectural Features

### 1. Per-Project Reply-To & Email Identification
* **Not Just a Dead No-Reply:** Every outgoing email includes a custom `Reply-To` header tailored per project (e.g. `support@abc.com` or `replies+abc@dhyey.cc`). When a user hits "Reply" in their email client, their response goes directly to that project's support team!
* **Smart Context Tracking:** Outgoing emails attach `X-Project-ID` and `X-Project-Name` headers, while the subject is cleanly tagged (e.g. `Reset Password - abc`). When a user replies, the subject arrives as `Re: Reset Password - abc`, immediately identifying the project.

### 2. Bring-Your-Own-SMTP (BYOS) — Offload Personal Email
* Other developers can provide their **own Gmail/business email and App Password** via the dashboard or API (`POST /api/project/smtp`).
* Once configured, all OTPs, resets, and broadcasts for that project are routed through **their own SMTP server**!
* **Zero quota or load** is placed on your personal email account.
* If a project does not configure custom SMTP, it seamlessly uses the platform's default fallback SMTP.

### 3. Priority Queue & Rate Limit Safety
* **⚡ High-Priority Instant Dispatch (OTPs & Resets):**
  * Time-critical operational emails (`/api/send-otp`, `/api/send-reset-password`) **bypass the queue completely**.
  * Delivered synchronously with immediate sub-second latency.
* **⏳ Low-Priority Broadcast Queue (Paced & Safe):**
  * Broadcast announcements (`/api/broadcast`, `/api/broadcast/all`) are persisted in MongoDB (`broadcast_jobs` and `broadcast_queue`).
  * Processed in the background with a configurable rate-limiting pacing delay (`BROADCAST_DELAY_SECONDS = 1.2s`) to stay safely below Gmail's burst thresholds (~30-40 emails/min).
  * Real-time progress monitoring endpoint (`GET /api/broadcast/status/<jobId>`).

### 4. Smart Unsubscribe & User Retention
* **Never Lost:** When users click Unsubscribe, they are **kept in the database** with `isSubscribed: false`.
* **Broadcasts Suppressed:** Broadcast emails are never delivered to unsubscribed users.
* **Mandatory Operational Emails Always Deliver:** Security emails (OTPs and password resets) always deliver regardless of unsubscribe status.
* **Auto-Reactivation:** If an unsubscribed user returns and uses a service again (requests an OTP or password reset), they are **automatically restored back to normal subscriber status**!
* **RFC 8058 One-Click Compliance:** Native `List-Unsubscribe: One-Click` headers for Gmail & Yahoo inbox compliance.

---

## 📁 Project Structure

```
personal-otp/
├── api/
│   └── index.py            # Flask API, queue processor, BYOS manager, SMTP engine
├── public/
│   ├── index.html          # Interactive developer portal, BYOS form & queue tracker
│   ├── app.js              # Tab switcher, live queue progress poller, BYOS tester
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

```env
# Database
MONGODB_URI=mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=otp_service
APP_URL=https://otp.dhyey.cc

# Security
MASTER_API_KEY=master_secret_change_me_12345
OTP_SECRET=random_32_byte_secret_string

# Default Platform SMTP (Fallback)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_personal_email@gmail.com
SMTP_PASSWORD=abcd efgh ijkl mnop
SMTP_FROM_EMAIL=your_personal_email@gmail.com
SMTP_FROM_NAME=Passcode
SMTP_REPLY_TO=support@dhyey.cc

# Queue Pacing Delay (Seconds between broadcast emails)
BROADCAST_DELAY_SECONDS=1.2
```

---

## 📡 API Reference

All requests must include your project's API key in the headers:
```http
X-API-Key: sk_abc_dev123
```
*(or `Authorization: Bearer sk_abc_dev123`)*

---

### 1. High-Priority Instant Endpoints

#### A. Send OTP (`POST /api/send-otp`)
* Immediate synchronous delivery. Remembers user in `subscribers`.
```json
{ "email": "user@example.com" }
```
* **Response:**
```json
{
  "success": true,
  "message": "Verification code sent to user@example.com",
  "project": "abc",
  "replyTo": "support+abc@dhyey.cc",
  "priority": "immediate",
  "expiresInMinutes": 5
}
```

#### B. Verify OTP (`POST /api/verify-otp`)
* Validates code and restores active status if user was previously unsubscribed.
```json
{ "email": "user@example.com", "otp": "593812" }
```

#### C. Send Password Reset (`POST /api/send-reset-password`)
* Immediate synchronous delivery.
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "reset_url": "https://yourapp.com/reset?token=xyz",
  "expires_in_minutes": 15
}
```

---

### 2. Bring-Your-Own-SMTP (BYOS)

#### Configure Custom SMTP for a Project (`POST /api/project/smtp`)
Assign custom credentials so a project sends via its own email account with zero platform load:
```json
{
  "host": "smtp.gmail.com",
  "port": 465,
  "secure": true,
  "user": "developer_email@gmail.com",
  "password": "developer_16_char_app_password",
  "from_email": "developer_email@gmail.com",
  "from_name": "Project XYZ Support",
  "reply_to": "support@projectxyz.com"
}
```

#### Check Project SMTP Status (`GET /api/project/smtp`)
Returns whether custom SMTP is active and the configured `replyTo` address.

#### Revert to Platform Default (`DELETE /api/project/smtp`)

---

### 3. Rate-Limited Broadcast Queue

#### A. Enqueue Project Broadcast (`POST /api/broadcast`)
Enqueues a broadcast to all active subscribers of the calling project:
```json
{
  "subject": "New Version 2.0 Released",
  "title": "Exciting Platform Updates!",
  "message": "<p>Here is what is new in version 2.0...</p>",
  "action_url": "https://yourapp.com/v2",
  "action_label": "View Features"
}
```
* **Response:**
```json
{
  "success": true,
  "message": "Broadcast enqueued for abc. Processing safely under rate limits.",
  "jobId": "job_abc_1731910000_a1b2",
  "totalRecipients": 120,
  "status": "queued",
  "priority": "low_queued",
  "rateLimitPacing": "1.2s per email"
}
```

#### B. Enqueue Global Broadcast across All Projects (`POST /api/broadcast/all`)
Requires `MASTER_API_KEY`. Dispatches to all unique users across all projects with email deduplication.

#### C. Poll Job Progress (`GET /api/broadcast/status/<job_id>`)
```json
{
  "success": true,
  "jobId": "job_abc_1731910000_a1b2",
  "status": "processing",
  "totalRecipients": 120,
  "sentCount": 45,
  "failedCount": 0,
  "progressPercent": 37.5
}
```

---

### 4. Subscribers & Unsubscribe
* `GET /api/subscribers` — Lists active and unsubscribed users recorded under the project.
* `GET /api/unsubscribe?project=abc&email=user@example.com&sig=...` — One-click unsubscribe confirmation page.
* `GET /api/resubscribe?...` — Undo unsubscribe.

---

## 💻 Client Integration Example (JavaScript)

```javascript
// High Priority: Send OTP instantly
const otpRes = await fetch("https://your-service.vercel.app/api/send-otp", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "sk_abc_dev123"
  },
  body: JSON.stringify({ email: "user@example.com" })
});
console.log(await otpRes.json());

// Low Priority: Enqueue broadcast safely
const bcastRes = await fetch("https://your-service.vercel.app/api/broadcast", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "sk_abc_dev123"
  },
  body: JSON.stringify({
    subject: "Platform Update",
    message: "<p>New updates are live!</p>"
  })
});
const job = await bcastRes.json();
console.log("Track broadcast progress at: /api/broadcast/status/" + job.jobId);
```

---

## 🚢 Deployment

### Deploying to Vercel
1. Run `vercel` in this project directory (or push to GitHub and import into Vercel).
2. Under **Project Settings > Environment Variables** on Vercel, paste the values from your `.env`.

### Custom Domain via Cloudflare (`dhyey.cc`)
1. In Vercel, add `otp.dhyey.cc` (or `api.dhyey.cc`).
2. In Cloudflare DNS for `dhyey.cc`, create a **CNAME** record:
   * **Name:** `otp`
   * **Target:** `cname.vercel-dns.com`
   * **Proxy status:** Proxied (Orange Cloud) or DNS only.
