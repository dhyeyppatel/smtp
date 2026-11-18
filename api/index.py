"""Multi-Project Email Gateway, OTP & Broadcast Service.

Features:
- Per-project API keys (e.g. project 'abc', project 'xyz').
- Per-project Reply-To support and routing headers (X-Project-ID, X-Project-Name).
- Bring-Your-Own-SMTP (BYOS): Projects can provide their own email & pass/app-password,
  completely removing load from the platform owner's personal email.
- Priority Queue Architecture:
    * High-Priority: OTPs, Password Resets, Critical emails (sent immediately).
    * Low-Priority Queue: Broadcasts (paced safely with rate-limiting delay,
      persisted in MongoDB broadcast_queue and broadcast_jobs).
- One-click unsubscribe system (GET & POST /api/unsubscribe) with RFC 8058 headers.
- Automatic project user retention per project with smart re-activation.
- Customizable Header & Footer per project and per email.
- Serverless ready (Vercel) & local runnable.
"""
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import socket
import ssl
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape

from flask import Flask, jsonify, request, send_from_directory
from pymongo import ASCENDING, MongoClient, ReturnDocument

# ==============================================================================
# Environment & Configuration
# ==============================================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    _env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(_env_file):
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k, _v = _k.strip(), _v.strip().strip('"').strip("'")
                    if _k not in os.environ:
                        os.environ[_k] = _v

MONGODB_URI = os.getenv("MONGODB_URI", "")
MONGODB_DB = os.getenv("MONGODB_DB", "otp_service")

MASTER_API_KEY = os.getenv("MASTER_API_KEY", "master_secret_change_me_12345")
OTP_SECRET = os.getenv("OTP_SECRET", "default_secret_please_change_in_production")
APP_URL = os.getenv("APP_URL", "")

# Default pre-seeded keys for Project 'abc' and Project 'xyz'
PROJECT_ABC_KEY = os.getenv("PROJECT_ABC_KEY", "sk_abc_dev123")
PROJECT_XYZ_KEY = os.getenv("PROJECT_XYZ_KEY", "sk_xyz_dev123")

# Default Platform SMTP Configuration (Fallback when projects don't provide custom SMTP)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USE_SSL = os.getenv("SMTP_SECURE", "true").lower() in ("true", "1", "yes") or SMTP_PORT == 465

# Backwards compatibility: fallback to GMAIL_USER / GMAIL_APP_PASSWORD if set
SMTP_USER = os.getenv("SMTP_USER") or os.getenv("GMAIL_USER", "")
_pwd_raw = os.getenv("SMTP_PASSWORD") or os.getenv("GMAIL_APP_PASSWORD", "")
SMTP_PASSWORD = _pwd_raw.replace(" ", "")

SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL") or SMTP_USER
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Passcode")
SMTP_REPLY_TO = os.getenv("SMTP_REPLY_TO", "")

# Rate limiting and Queue settings
OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "5"))
RESEND_COOLDOWN = int(os.getenv("RESEND_COOLDOWN_SECONDS", "60"))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "5"))
IP_HOURLY_LIMIT = int(os.getenv("IP_HOURLY_LIMIT", "30"))
BROADCAST_DELAY_SECONDS = float(os.getenv("BROADCAST_DELAY_SECONDS", "1.2"))

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024  # 32 KB body limit


class VercelPathRewriteMiddleware:
    """WSGI middleware ensuring proper sub-routing when deployed as a single serverless function on Vercel."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        # Check if request was routed or rewritten to the entrypoint
        if path in ("/api/index", "/api/index/", "/api", "/api/"):
            # 1. Edge rewrite header (Vercel)
            matched = (
                environ.get("HTTP_X_MATCHED_PATH")
                or environ.get("HTTP_X_FORWARDED_URI")
                or environ.get("HTTP_X_INVOKE_PATH")
            )
            if matched and matched.startswith("/api/") and matched not in ("/api/index", "/api/index/"):
                environ["PATH_INFO"] = matched.split("?")[0]
            else:
                # 2. Query string fallback from vercel.json rewrite rule
                qs = environ.get("QUERY_STRING", "")
                if qs:
                    params = urllib.parse.parse_qs(qs)
                    vpath = params.get("__vpath", [None])[0] or params.get("__path", [None])[0]
                    if vpath:
                        clean_vpath = vpath.lstrip("/")
                        environ["PATH_INFO"] = f"/api/{clean_vpath}"
                        # Filter out internal query parameters
                        filtered = [
                            (k, v)
                            for k, vals in params.items()
                            if k not in ("__vpath", "__path")
                            for v in vals
                        ]
                        environ["QUERY_STRING"] = urllib.parse.urlencode(filtered)

        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathRewriteMiddleware(app.wsgi_app)


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        res = jsonify({"status": "ok"})
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization, X-Project-Name"
        return res, 200


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization, X-Project-Name"
    return response

_client = None
_initialized = False


# ==============================================================================
# Database & Initialization
# ==============================================================================
def get_db():
    """Lazy MongoDB connection with auto-indexing and project seeding."""
    global _client, _initialized
    if not MONGODB_URI:
        raise RuntimeError("MONGODB_URI environment variable is not set.")
    if _client is None:
        _client = MongoClient(MONGODB_URI, tz_aware=True, serverSelectionTimeoutMS=5000)
    db = _client[MONGODB_DB]

    if not _initialized:
        # TTL auto-expiration indexes
        db.otps.create_index([("expiresAt", ASCENDING)], expireAfterSeconds=0)
        db.rate_limits.create_index([("expireAt", ASCENDING)], expireAfterSeconds=0)
        db.projects.create_index([("apiKey", ASCENDING)], unique=True)
        db.subscribers.create_index([("projectId", ASCENDING), ("isSubscribed", ASCENDING)])
        db.subscribers.create_index([("email", ASCENDING)])
        db.broadcast_jobs.create_index([("createdAt", ASCENDING)])
        db.broadcast_queue.create_index([("jobId", ASCENDING), ("status", ASCENDING)])

        # Auto-seed initial projects 'abc' and 'xyz' if collection is empty
        try:
            if db.projects.count_documents({}) == 0:
                now_t = datetime.now(timezone.utc)
                db.projects.insert_many([
                    {
                        "_id": "abc",
                        "name": "abc",
                        "apiKey": PROJECT_ABC_KEY,
                        "fromName": "abc",
                        "replyToEmail": "support+abc@dhyey.cc",
                        "headerTitle": "Project abc",
                        "footerText": "© 2026 Project abc. All rights reserved.",
                        "smtp": {"enabled": False},
                        "isActive": True,
                        "createdAt": now_t,
                    },
                    {
                        "_id": "xyz",
                        "name": "xyz",
                        "apiKey": PROJECT_XYZ_KEY,
                        "fromName": "xyz",
                        "replyToEmail": "support+xyz@dhyey.cc",
                        "headerTitle": "Project xyz",
                        "footerText": "© 2026 Project xyz. All rights reserved.",
                        "smtp": {"enabled": False},
                        "isActive": True,
                        "createdAt": now_t,
                    },
                ])
        except Exception:
            pass  # Ignore seed errors if already populated or under race

        _initialized = True

    return db


def now():
    return datetime.now(timezone.utc)


def fail(code, message, status=400, **extra):
    return jsonify({"success": False, "code": code, "error": message, **extra}), status


def client_ip():
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or request.remote_addr or "unknown"


def hash_otp(project_id, email, otp):
    payload = f"{project_id}:{email}:{otp}".encode()
    return hmac.new(OTP_SECRET.encode(), payload, hashlib.sha256).hexdigest()


# ==============================================================================
# Subscriber Retention & Unsubscribe Tokens
# ==============================================================================
def record_subscriber(project_id, email, name=None, source="auto", reactivate=True):
    """Auto-remembers user email under the given project.
    
    If reactivate=True (e.g. from OTP, Reset Password, or Service interaction),
    an unsubscribed user is automatically restored back to a normal subscriber.
    """
    try:
        db = get_db()
        t = now()
        update_fields = {
            "updatedAt": t,
            "email": email,
            "projectId": project_id,
            "lastAction": source,
        }
        if name:
            update_fields["name"] = name

        if reactivate:
            # Re-activates them back to a normal subscriber
            update_fields["isSubscribed"] = True
            update_fields["unsubscribedAt"] = None
            update_fields["resubscribedAt"] = t

        db.subscribers.update_one(
            {"_id": f"{project_id}:{email}"},
            {
                "$set": update_fields,
                "$setOnInsert": {
                    "createdAt": t,
                    "source": source,
                },
            },
            upsert=True,
        )
    except Exception:
        pass


def make_unsub_sig(project_id, email):
    """Generates a secure HMAC signature for one-click unsubscribe links."""
    raw = f"unsub:{project_id}:{email}".encode()
    return hmac.new(OTP_SECRET.encode(), raw, hashlib.sha256).hexdigest()[:16]


def get_unsub_url(project_id, email):
    """Returns the full public unsubscribe URL for a specific project and email."""
    base = (APP_URL or request.host_url).rstrip("/")
    sig = make_unsub_sig(project_id, email)
    return f"{base}/api/unsubscribe?project={project_id}&email={email}&sig={sig}"


# ==============================================================================
# Authentication & Project Resolution
# ==============================================================================
def get_api_key_from_request():
    """Extracts API key from X-API-Key or Authorization: Bearer header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return request.headers.get("X-API-Key", "").strip()


def resolve_project():
    """Authenticates the incoming request and returns the project dictionary.

    Returns: (project_dict, None) or (None, (json_response, status_code))
    """
    key = get_api_key_from_request()
    if not key:
        return None, fail("unauthorized", "API key required via 'X-API-Key' or 'Authorization: Bearer <key>' header.", 401)

    # Master key override
    if MASTER_API_KEY and key == MASTER_API_KEY:
        req_data = request.get_json(silent=True) or {}
        proj_name = request.headers.get("X-Project-Name") or req_data.get("project") or "System"
        return {
            "_id": proj_name.lower().replace(" ", "_"),
            "name": proj_name,
            "fromName": proj_name,
            "replyToEmail": SMTP_REPLY_TO or f"support+{proj_name.lower()}@dhyey.cc",
            "apiKey": MASTER_API_KEY,
            "isMaster": True,
            "isActive": True,
        }, None

    # First attempt DB lookup so custom SMTP and settings are fresh
    try:
        db = get_db()
        project = db.projects.find_one({"apiKey": key, "isActive": True})
        if project:
            return project, None
    except Exception:
        pass

    # Fast-path fallback for pre-configured project keys if DB is offline
    if PROJECT_ABC_KEY and key == PROJECT_ABC_KEY:
        return {
            "_id": "abc",
            "name": "abc",
            "fromName": "abc",
            "replyToEmail": "support+abc@dhyey.cc",
            "headerTitle": "Project abc",
            "footerText": "© 2026 Project abc. All rights reserved.",
            "apiKey": PROJECT_ABC_KEY,
            "isActive": True,
        }, None
    if PROJECT_XYZ_KEY and key == PROJECT_XYZ_KEY:
        return {
            "_id": "xyz",
            "name": "xyz",
            "fromName": "xyz",
            "replyToEmail": "support+xyz@dhyey.cc",
            "headerTitle": "Project xyz",
            "footerText": "© 2026 Project xyz. All rights reserved.",
            "apiKey": PROJECT_XYZ_KEY,
            "isActive": True,
        }, None

    return None, fail("forbidden", "Invalid or revoked API key.", 403)


# ==============================================================================
# Subject, From & Reply-To Formatting
# ==============================================================================
def format_subject(base_subject, project):
    """Ensures the subject line cleanly includes the project name.

    E.g. "Reset Password" -> "Reset Password - abc"
    """
    proj_name = project.get("name", "Passcode") if isinstance(project, dict) else str(project)
    base = (base_subject or "").strip()
    suffix = f"- {proj_name}"

    if not base:
        return proj_name
    if base.endswith(suffix) or f"[{proj_name}]" in base:
        return base
    return f"{base} {suffix}"


def format_from(project):
    """Resolves From header respecting custom BYOS credentials if enabled."""
    custom_smtp = project.get("smtp", {}) if isinstance(project, dict) else {}
    if custom_smtp.get("enabled") and custom_smtp.get("fromEmail"):
        from_name = custom_smtp.get("fromName") or project.get("fromName") or project.get("name") or "Passcode"
        return f"{from_name} <{custom_smtp['fromEmail']}>"

    name = project.get("fromName") or project.get("name") or SMTP_FROM_NAME
    return f"{name} <{SMTP_FROM_EMAIL}>"


def format_reply_to(project, custom_reply_to=None):
    """Resolves per-project Reply-To header.

    When recipients hit Reply, their email client directs the message here.
    """
    if custom_reply_to:
        return custom_reply_to

    # 1. Check project custom reply-to
    if isinstance(project, dict) and project.get("replyToEmail"):
        return project["replyToEmail"]

    # 2. Check custom SMTP user email if provided
    custom_smtp = project.get("smtp", {}) if isinstance(project, dict) else {}
    if custom_smtp.get("enabled") and custom_smtp.get("replyTo"):
        return custom_smtp["replyTo"]
    if custom_smtp.get("enabled") and custom_smtp.get("user"):
        return custom_smtp["user"]

    # 3. Fallback: subaddress or platform reply-to
    proj_name = project.get("name", "support") if isinstance(project, dict) else "support"
    if SMTP_REPLY_TO:
        return SMTP_REPLY_TO
    if SMTP_FROM_EMAIL and "@" in SMTP_FROM_EMAIL:
        user, domain = SMTP_FROM_EMAIL.split("@", 1)
        return f"{user}+{proj_name.lower()}@{domain}"

    return SMTP_FROM_EMAIL


# ==============================================================================
# HTML Email Templates
# ==============================================================================
def render_email_shell(project, inner_html, custom_header=None, custom_footer=None, unsub_url=None):
    """Responsive branded HTML shell with custom header, footer, and Reply-To note."""
    project_name = project.get("name", "Passcode") if isinstance(project, dict) else str(project)
    safe_name = escape(project_name)

    # 1. Header Resolution
    header_logo = project.get("headerLogoUrl") if isinstance(project, dict) else None
    header_title = project.get("headerTitle") if isinstance(project, dict) else safe_name

    if custom_header:
        header_block = f"""<div style="padding:20px 24px;border-bottom:1px solid #F2F4F7;">{custom_header}</div>"""
    elif header_logo:
        header_block = f"""
        <div style="padding:20px 24px;border-bottom:1px solid #F2F4F7;">
          <img src="{escape(header_logo)}" alt="{safe_name}" style="max-height:36px;display:block;">
        </div>"""
    else:
        header_block = f"""
        <div style="padding:20px 24px;border-bottom:1px solid #F2F4F7;">
          <span style="font-size:16px;font-weight:700;color:#1F3FD1;letter-spacing:-0.01em;">{escape(header_title or safe_name)}</span>
        </div>"""

    # 2. Footer Resolution
    footer_text = custom_footer or (project.get("footerText") if isinstance(project, dict) else f"Automated message for {safe_name}")
    unsub_block = ""
    if unsub_url:
        unsub_block = f"""
        <p style="margin:10px 0 0;font-size:11px;color:#98A2B3;">
          Don't want to receive these emails? <a href="{escape(unsub_url)}" style="color:#667085;text-decoration:underline;">Unsubscribe from {safe_name}</a>
        </p>"""

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:24px;background-color:#F2F4F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#101828;">
  <div style="max-width:520px;margin:0 auto;background:#FFFFFF;border-radius:12px;border:1px solid #E4E7EC;overflow:hidden;box-shadow:0 4px 12px rgba(16,24,40,0.05);">
    {header_block}
    <div style="padding:28px 24px;">
      {inner_html}
    </div>
    <div style="padding:18px 24px;background:#FAFAFB;border-top:1px solid #F2F4F7;text-align:center;">
      <p style="margin:0;font-size:12px;color:#667085;">{escape(footer_text)}</p>
      {unsub_block}
    </div>
  </div>
</body>
</html>"""


def render_otp_template(project, otp, ttl_minutes):
    project_name = project.get("name") if isinstance(project, dict) else str(project)
    inner = f"""
      <h2 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#101828;">Verification Code</h2>
      <p style="margin:0 0 20px;font-size:14px;color:#475467;line-height:1.5;">
        Use this single-use code to complete your verification for <strong>{escape(project_name)}</strong>.
      </p>
      <div style="background:#F8F9FC;border:1px dashed #D0D5DD;border-radius:8px;padding:18px;text-align:center;margin:0 0 20px;">
        <span style="font-size:36px;font-weight:800;letter-spacing:10px;color:#1F3FD1;font-family:ui-monospace,Menlo,Consolas,monospace;">{escape(otp)}</span>
      </div>
      <p style="margin:0;font-size:13px;color:#667085;line-height:1.4;">
        This code expires in <strong>{ttl_minutes} minutes</strong>. If you did not request this code, you can safely ignore this email.
      </p>
    """
    return render_email_shell(project, inner)


def render_reset_password_template(project, reset_url=None, reset_code=None, name=None, expires_in=15):
    project_name = project.get("name") if isinstance(project, dict) else str(project)
    greeting = f"Hello {escape(name)}," if name else "Hello,"
    action_block = ""
    if reset_url:
        action_block += f"""
        <div style="text-align:center;margin:24px 0;">
          <a href="{escape(reset_url)}" target="_blank" style="background:#1F3FD1;color:#FFFFFF;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;display:inline-block;">Reset Password</a>
        </div>
        """
    if reset_code:
        action_block += f"""
        <p style="margin:16px 0 6px;font-size:13px;color:#475467;text-align:center;">Or enter this reset code:</p>
        <div style="background:#F8F9FC;border:1px solid #D0D5DD;border-radius:8px;padding:12px;text-align:center;margin:0 0 20px;">
          <span style="font-size:24px;font-weight:700;letter-spacing:6px;color:#101828;font-family:ui-monospace,Menlo,Consolas,monospace;">{escape(reset_code)}</span>
        </div>
        """

    inner = f"""
      <h2 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#101828;">Reset Your Password</h2>
      <p style="margin:0 0 16px;font-size:14px;color:#475467;line-height:1.5;">
        {greeting}<br>
        We received a request to reset your password for your <strong>{escape(project_name)}</strong> account.
      </p>
      {action_block}
      <p style="margin:0;font-size:13px;color:#667085;line-height:1.4;">
        This link and code will expire in {expires_in} minutes. If you did not request a password reset, please ignore this email or review your account security.
      </p>
    """
    return render_email_shell(project, inner)


def render_greeting_template(project, title, message, name=None, action_url=None, action_label=None, unsub_url=None):
    greeting = f"Hello {escape(name)}," if name else "Hello,"
    button_html = ""
    if action_url:
        btn_text = escape(action_label or "Get Started")
        button_html = f"""
        <div style="text-align:center;margin:24px 0 16px;">
          <a href="{escape(action_url)}" target="_blank" style="background:#1F3FD1;color:#FFFFFF;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;display:inline-block;">{btn_text}</a>
        </div>
        """

    inner = f"""
      <h2 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#101828;">{escape(title)}</h2>
      <p style="margin:0 0 12px;font-size:14px;color:#475467;line-height:1.5;">{greeting}</p>
      <div style="font-size:14px;color:#344054;line-height:1.6;margin:0 0 16px;">
        {message}
      </div>
      {button_html}
    """
    return render_email_shell(project, inner, unsub_url=unsub_url)


def render_broadcast_template(project, title, message, action_url=None, action_label=None, custom_header=None, custom_footer=None, unsub_url=None):
    button_html = ""
    if action_url:
        btn_text = escape(action_label or "View Details")
        button_html = f"""
        <div style="text-align:center;margin:24px 0 16px;">
          <a href="{escape(action_url)}" target="_blank" style="background:#1F3FD1;color:#FFFFFF;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;display:inline-block;">{btn_text}</a>
        </div>
        """

    inner = f"""
      <h2 style="margin:0 0 12px;font-size:22px;font-weight:700;color:#101828;">{escape(title)}</h2>
      <div style="font-size:15px;color:#344054;line-height:1.6;margin:0 0 20px;">
        {message}
      </div>
      {button_html}
    """
    return render_email_shell(project, inner, custom_header=custom_header, custom_footer=custom_footer, unsub_url=unsub_url)


# ==============================================================================
# SMTP Delivery Engine (With BYOS & Reply-To Routing)
# ==============================================================================
def _smtp_login(server, user, password):
    """Logs into the SMTP server, accurately identifying provider credential rejections."""
    try:
        server.login(user, password)
    except smtplib.SMTPAuthenticationError:
        raise
    except smtplib.SMTPServerDisconnected as err:
        # Many providers (like Gmail) immediately close the socket on invalid credentials / revoked app passwords
        raise smtplib.SMTPAuthenticationError(
            535,
            b"Username and password not accepted by SMTP server (BadCredentials). Check your Gmail App Password and 2FA.",
        ) from err


def send_email_message(to_email, subject, text_content, html_content, from_header, unsub_url=None, reply_to=None, project=None):
    """Robust SMTP dispatcher supporting BYOS (Bring-Your-Own-SMTP) and project routing."""
    # Check if project has configured its own custom SMTP
    custom_smtp = (project.get("smtp", {}) if isinstance(project, dict) else {}) or {}
    use_custom = custom_smtp.get("enabled") and custom_smtp.get("user") and custom_smtp.get("password")

    if use_custom:
        host = custom_smtp.get("host") or "smtp.gmail.com"
        port = int(custom_smtp.get("port", 465))
        use_ssl = custom_smtp.get("secure", True) or port == 465
        user = custom_smtp.get("user", "")
        password = str(custom_smtp.get("password", "")).replace(" ", "")
    else:
        host = SMTP_HOST
        port = SMTP_PORT
        use_ssl = SMTP_USE_SSL
        user = SMTP_USER
        password = SMTP_PASSWORD

    if not user or not password:
        raise smtplib.SMTPAuthenticationError(535, b"SMTP credentials are not configured.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to_email

    # Routing & Reply-To Headers
    if reply_to:
        msg["Reply-To"] = reply_to
    if isinstance(project, dict):
        msg["X-Project-ID"] = str(project.get("_id", ""))
        msg["X-Project-Name"] = str(project.get("name", ""))

    # RFC 8058 One-Click List-Unsubscribe Header
    if unsub_url:
        msg["List-Unsubscribe"] = f"<{unsub_url}>"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    if text_content:
        msg.set_content(text_content)
    if html_content:
        msg.add_alternative(html_content, subtype="html")

    context = ssl.create_default_context()

    if use_ssl or port == 465:
        try:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=12) as server:
                _smtp_login(server, user, password)
                server.send_message(msg)
                return
        except smtplib.SMTPAuthenticationError:
            raise
        except (socket.timeout, OSError) as ssl_err:
            app.logger.warning("Port 465 SSL connection failed (%s). Auto-attempting port 587 STARTTLS...", ssl_err)

    # Port 587 STARTTLS (or configured port)
    fallback_port = 587 if port == 465 else port
    with smtplib.SMTP(host, fallback_port, timeout=15) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        _smtp_login(server, user, password)
        server.send_message(msg)


# ==============================================================================
# Rate-Limited Broadcast Queue Processor
# ==============================================================================
def process_broadcast_queue_job(job_id):
    """Processes a broadcast job safely with rate-limit pacing delay."""
    try:
        db = get_db()
        job = db.broadcast_jobs.find_one({"_id": job_id})
        if not job or job.get("status") == "completed":
            return

        db.broadcast_jobs.update_one({"_id": job_id}, {"$set": {"status": "processing", "startedAt": now()}})

        project = db.projects.find_one({"_id": job["projectId"]}) or {
            "_id": job["projectId"],
            "name": job.get("projectName", job["projectId"]),
            "fromName": job.get("projectName", job["projectId"]),
        }

        # Fetch pending recipient items
        pending_items = list(db.broadcast_queue.find({"jobId": job_id, "status": "pending"}))
        from_header = format_from(project)
        reply_to = format_reply_to(project)

        for item in pending_items:
            recipient = item["email"]
            unsub_url = get_unsub_url(str(project["_id"]), recipient)
            html_body = render_broadcast_template(
                project,
                job["title"],
                job["message"],
                job.get("actionUrl"),
                job.get("actionLabel"),
                job.get("customHeader"),
                job.get("customFooter"),
                unsub_url,
            )
            text_body = f"{job['title']}\n\n{job['message']}\n\nUnsubscribe: {unsub_url}"

            try:
                send_email_message(recipient, job["subject"], text_body, html_body, from_header, unsub_url, reply_to, project)
                db.broadcast_queue.update_one({"_id": item["_id"]}, {"$set": {"status": "sent", "sentAt": now()}})
                db.broadcast_jobs.update_one({"_id": job_id}, {"$inc": {"sentCount": 1}})
            except Exception as e:
                db.broadcast_queue.update_one(
                    {"_id": item["_id"]},
                    {"$set": {"status": "failed", "error": str(e), "failedAt": now()}, "$inc": {"attempts": 1}},
                )
                db.broadcast_jobs.update_one({"_id": job_id}, {"$inc": {"failedCount": 1}})

            # Safe rate limit delay to avoid hitting SMTP burst barriers
            if BROADCAST_DELAY_SECONDS > 0:
                time.sleep(BROADCAST_DELAY_SECONDS)

        db.broadcast_jobs.update_one({"_id": job_id}, {"$set": {"status": "completed", "completedAt": now()}})
    except Exception as exc:
        app.logger.exception("Error processing broadcast queue job %s: %s", job_id, exc)


# ==============================================================================
# API Endpoints
# ==============================================================================
@app.route("/api/health", methods=["GET", "OPTIONS"], strict_slashes=False)
def health():
    """Health & Readiness probe reporting DB and SMTP status."""
    smtp_ok = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and SMTP_FROM_EMAIL)
    db_ok = False
    try:
        db = get_db()
        db.command("ping")
        db_ok = True
    except Exception:
        db_ok = False

    all_ok = smtp_ok and db_ok
    return jsonify({
        "status": "ok" if all_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "smtp": {
            "configured": smtp_ok,
            "host": SMTP_HOST,
            "port": SMTP_PORT,
            "secure": SMTP_USE_SSL,
            "from_email": SMTP_FROM_EMAIL,
        },
    }), (200 if all_ok else 503)


# ------------------------------------------------------------------------------
# 1. Send OTP (High-Priority: Synchronous Direct Dispatch)
# ------------------------------------------------------------------------------
@app.route("/api/send-otp", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
@app.route("/api/resend-otp", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def send_otp():
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'email': '...'}", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not email or len(email) > 254 or not EMAIL_RE.match(email):
        return fail("invalid_email", "Enter a valid email address.", 400)

    db = get_db()
    project_id = str(project["_id"])
    scoped_id = f"{project_id}:{email}"

    # Rate limiting by IP
    bucket = int(time.time() // 3600)
    hits = db.rate_limits.find_one_and_update(
        {"_id": f"{client_ip()}:{bucket}"},
        {"$inc": {"n": 1}, "$setOnInsert": {"expireAt": now() + timedelta(hours=2)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if hits["n"] > IP_HOURLY_LIMIT:
        return fail("rate_limited", "Too many requests from your network. Try again later.", 429)

    # Check cooldown for this project + email
    existing = db.otps.find_one({"_id": scoped_id})
    if existing:
        wait = RESEND_COOLDOWN - (now() - existing["lastSentAt"]).total_seconds()
        if wait > 0:
            return fail("cooldown", f"Wait {int(wait) + 1}s before requesting another code.", 429,
                        retryAfter=int(wait) + 1)

    otp = f"{secrets.randbelow(10**6):06d}"
    subject = format_subject(f"{otp} is your verification code", project)
    html_body = render_otp_template(project, otp, OTP_TTL_MINUTES)
    text_body = f"Your verification code for {project['name']} is {otp}. It expires in {OTP_TTL_MINUTES} minutes."
    from_header = format_from(project)
    reply_to = format_reply_to(project, data.get("reply_to"))

    # Direct immediate dispatch (bypasses low-priority broadcast queue)
    try:
        send_email_message(email, subject, text_body, html_body, from_header, reply_to=reply_to, project=project)
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = auth_err.smtp_error.decode("utf-8", errors="ignore") if isinstance(getattr(auth_err, "smtp_error", None), bytes) else str(getattr(auth_err, "smtp_error", "") or auth_err or "Invalid credentials")
        return fail("smtp_auth", f"SMTP authentication failed: {err_msg}", 502)
    except (smtplib.SMTPException, OSError) as net_err:
        return fail("smtp_unreachable", f"Couldn't send the email: {net_err}", 502)

    t = now()
    db.otps.replace_one(
        {"_id": scoped_id},
        {
            "_id": scoped_id,
            "projectId": project_id,
            "email": email,
            "hash": hash_otp(project_id, email, otp),
            "attempts": 0,
            "lastSentAt": t,
            "expiresAt": t + timedelta(minutes=OTP_TTL_MINUTES),
        },
        upsert=True,
    )

    # Automatically remember/reactivate user email for this project
    record_subscriber(project_id, email, source="otp", reactivate=True)

    return jsonify({
        "success": True,
        "message": f"Verification code sent to {email}",
        "project": project["name"],
        "replyTo": reply_to,
        "priority": "immediate",
        "expiresInMinutes": OTP_TTL_MINUTES,
        "cooldownSeconds": RESEND_COOLDOWN,
    })


# ------------------------------------------------------------------------------
# 2. Verify OTP (High-Priority: Synchronous Direct Verification)
# ------------------------------------------------------------------------------
@app.route("/api/verify-otp", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def verify_otp():
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'email': '...', 'otp': '...'}", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    otp = str(data.get("otp", "")).strip()

    if not email or not EMAIL_RE.match(email):
        return fail("invalid_email", "Enter a valid email address.", 400)
    if not re.fullmatch(r"\d{6}", otp):
        return fail("invalid_otp_format", "The code must be exactly 6 digits.", 400)

    db = get_db()
    project_id = str(project["_id"])
    scoped_id = f"{project_id}:{email}"

    doc = db.otps.find_one({"_id": scoped_id})
    if not doc:
        return fail("no_otp", "No active code for this email. Request a new one.", 404)
    if doc["expiresAt"] <= now():
        db.otps.delete_one({"_id": scoped_id})
        return fail("expired", "That code has expired. Request a new one.", 410)
    if doc["attempts"] >= MAX_ATTEMPTS:
        db.otps.delete_one({"_id": scoped_id})
        return fail("too_many_attempts", "Too many wrong attempts. Request a new code.", 429)

    expected_hash = hash_otp(project_id, email, otp)
    if hmac.compare_digest(doc["hash"], expected_hash):
        res = db.otps.delete_one({"_id": scoped_id, "hash": doc["hash"]})
        if res.deleted_count == 1:
            record_subscriber(project_id, email, source="verified_otp", reactivate=True)
            return jsonify({
                "success": True,
                "message": f"Email verified successfully for {project['name']}.",
                "project": project["name"],
                "email": email,
            })
        return fail("no_otp", "That code was already used. Request a new one.", 404)

    updated = db.otps.find_one_and_update(
        {"_id": scoped_id}, {"$inc": {"attempts": 1}}, return_document=ReturnDocument.AFTER
    )
    left = MAX_ATTEMPTS - (updated["attempts"] if updated else MAX_ATTEMPTS)
    if left <= 0:
        db.otps.delete_one({"_id": scoped_id})
        return fail("too_many_attempts", "Too many wrong attempts. Request a new code.", 429)

    return fail("invalid_otp", f"Wrong code. {left} attempt{'s' if left != 1 else ''} left.", 401,
                attemptsLeft=left)


# ------------------------------------------------------------------------------
# 3. Send Reset Password Email (High-Priority: Synchronous Direct Dispatch)
# ------------------------------------------------------------------------------
@app.route("/api/send-reset-password", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def send_reset_password():
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'email': '...', 'reset_url': '...'}", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not email or not EMAIL_RE.match(email):
        return fail("invalid_email", "Enter a valid email address.", 400)

    reset_url = data.get("reset_url")
    reset_code = data.get("reset_code")
    name = data.get("name")
    expires_in = int(data.get("expires_in_minutes", 15))
    custom_subject = data.get("subject") or "Reset Password"

    if not reset_url and not reset_code:
        return fail("missing_parameters", "Provide either 'reset_url' or 'reset_code'.", 400)

    subject = format_subject(custom_subject, project)
    html_body = render_reset_password_template(project, reset_url, reset_code, name, expires_in)
    text_body = f"Reset password for {project['name']}: {reset_url or reset_code}"
    from_header = format_from(project)
    reply_to = format_reply_to(project, data.get("reply_to"))

    # Direct immediate dispatch
    try:
        send_email_message(email, subject, text_body, html_body, from_header, reply_to=reply_to, project=project)
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = auth_err.smtp_error.decode("utf-8", errors="ignore") if isinstance(getattr(auth_err, "smtp_error", None), bytes) else str(getattr(auth_err, "smtp_error", "") or auth_err or "Invalid credentials")
        return fail("smtp_auth", f"SMTP authentication failed ({err_msg}). Check credentials.", 502)
    except Exception as e:
        app.logger.exception(e)
        return fail("smtp_unreachable", f"Couldn't send reset password email: {e}", 502)

    record_subscriber(str(project["_id"]), email, name=name, source="reset_password", reactivate=True)

    return jsonify({
        "success": True,
        "message": f"Password reset email sent to {email}",
        "subject": subject,
        "replyTo": reply_to,
        "priority": "immediate",
        "project": project["name"],
    })


# ------------------------------------------------------------------------------
# 4. Send Greeting / Welcome Email
# ------------------------------------------------------------------------------
@app.route("/api/send-greeting", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def send_greeting():
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload.", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not email or not EMAIL_RE.match(email):
        return fail("invalid_email", "Enter a valid email address.", 400)

    project_id = str(project["_id"])
    title = data.get("title") or f"Welcome to {project['name']}!"
    message = data.get("message") or f"<p>We're thrilled to have you join us at <strong>{escape(project['name'])}</strong>.</p>"
    name = data.get("name")
    action_url = data.get("action_url")
    action_label = data.get("action_label")
    custom_subject = data.get("subject") or f"Welcome - {project['name']}"

    unsub_url = get_unsub_url(project_id, email)
    subject = format_subject(custom_subject, project)
    html_body = render_greeting_template(project, title, message, name, action_url, action_label, unsub_url)
    text_body = f"{title}\n\nWelcome to {project['name']}!\n\nUnsubscribe: {unsub_url}"
    from_header = format_from(project)
    reply_to = format_reply_to(project, data.get("reply_to"))

    try:
        send_email_message(email, subject, text_body, html_body, from_header, unsub_url=unsub_url, reply_to=reply_to, project=project)
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = auth_err.smtp_error.decode("utf-8", errors="ignore") if isinstance(getattr(auth_err, "smtp_error", None), bytes) else str(getattr(auth_err, "smtp_error", "") or auth_err or "Invalid credentials")
        return fail("smtp_auth", f"SMTP authentication failed ({err_msg}). Check credentials.", 502)
    except Exception as e:
        app.logger.exception(e)
        return fail("smtp_unreachable", f"Couldn't send greeting email: {e}", 502)

    record_subscriber(project_id, email, name=name, source="greeting", reactivate=True)

    return jsonify({
        "success": True,
        "message": f"Greeting sent to {email}",
        "subject": subject,
        "replyTo": reply_to,
        "project": project["name"],
    })


# ------------------------------------------------------------------------------
# 5. Generic / Custom Email Dispatch
# ------------------------------------------------------------------------------
@app.route("/api/send-mail", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def send_mail_custom():
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'to': '...', 'subject': '...'}", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    to_email = str(data.get("to", "")).strip().lower()
    subject_raw = str(data.get("subject", "")).strip()
    html_raw = data.get("html")
    text_raw = data.get("text", "")
    custom_header = data.get("custom_header")
    custom_footer = data.get("custom_footer")
    include_unsub = data.get("include_unsubscribe", True)

    if not to_email or not EMAIL_RE.match(to_email):
        return fail("invalid_email", "Enter a valid 'to' email address.", 400)
    if not subject_raw:
        return fail("invalid_subject", "'subject' is required.", 400)
    if not html_raw and not text_raw:
        return fail("invalid_content", "Either 'html' or 'text' content is required.", 400)

    project_id = str(project["_id"])
    unsub_url = get_unsub_url(project_id, to_email) if include_unsub else None
    subject = format_subject(subject_raw, project)
    html_body = render_email_shell(project, html_raw, custom_header=custom_header, custom_footer=custom_footer, unsub_url=unsub_url) if html_raw else None
    from_header = format_from(project)
    reply_to = format_reply_to(project, data.get("reply_to"))

    try:
        send_email_message(to_email, subject, text_raw, html_body, from_header, unsub_url=unsub_url, reply_to=reply_to, project=project)
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = auth_err.smtp_error.decode("utf-8", errors="ignore") if isinstance(getattr(auth_err, "smtp_error", None), bytes) else str(getattr(auth_err, "smtp_error", "") or auth_err or "Invalid credentials")
        return fail("smtp_auth", f"SMTP authentication failed ({err_msg}). Check credentials.", 502)
    except Exception as e:
        app.logger.exception(e)
        return fail("smtp_unreachable", f"Couldn't send email: {e}", 502)

    record_subscriber(project_id, to_email, source="custom_mail", reactivate=True)

    return jsonify({
        "success": True,
        "message": f"Email delivered to {to_email}",
        "subject": subject,
        "replyTo": reply_to,
        "project": project["name"],
    })


# ------------------------------------------------------------------------------
# 6. Broadcast Queue & Job Endpoints (Rate-Limited, Non-Blocking)
# ------------------------------------------------------------------------------
@app.route("/api/broadcast", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def enqueue_project_broadcast():
    """Enqueues a broadcast message to all active subscribers for safe rate-limited delivery."""
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'subject': '...', 'message': '...'}", 400)

    project, err = resolve_project()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    subject_raw = str(data.get("subject", "")).strip()
    title = str(data.get("title") or subject_raw).strip()
    message = str(data.get("message", "")).strip()
    action_url = data.get("action_url")
    action_label = data.get("action_label")
    custom_header = data.get("custom_header")
    custom_footer = data.get("custom_footer")

    if not subject_raw or not message:
        return fail("invalid_parameters", "'subject' and 'message' are required.", 400)

    db = get_db()
    project_id = str(project["_id"])
    subscribers = list(db.subscribers.find({"projectId": project_id, "isSubscribed": True}))

    if not subscribers:
        return jsonify({
            "success": True,
            "message": f"No active subscribers found for project '{project['name']}'.",
            "jobId": None,
            "totalRecipients": 0,
        })

    subject = format_subject(subject_raw, project)
    job_id = f"job_{project_id}_{int(time.time())}_{secrets.token_hex(4)}"

    # 1. Create Broadcast Job Document
    job_doc = {
        "_id": job_id,
        "projectId": project_id,
        "projectName": project["name"],
        "subject": subject,
        "title": title,
        "message": message,
        "actionUrl": action_url,
        "actionLabel": action_label,
        "customHeader": custom_header,
        "customFooter": custom_footer,
        "totalRecipients": len(subscribers),
        "sentCount": 0,
        "failedCount": 0,
        "status": "queued",
        "createdAt": now(),
    }
    db.broadcast_jobs.insert_one(job_doc)

    # 2. Enqueue all recipients
    queue_items = [
        {
            "_id": f"{job_id}:{sub['email']}",
            "jobId": job_id,
            "projectId": project_id,
            "email": sub["email"],
            "status": "pending",
            "attempts": 0,
            "createdAt": now(),
        }
        for sub in subscribers
        if sub.get("email")
    ]
    if queue_items:
        db.broadcast_queue.insert_many(queue_items)

    # 3. Launch background worker thread for throttled dispatch
    threading.Thread(target=process_broadcast_queue_job, args=(job_id,), daemon=True).start()

    return jsonify({
        "success": True,
        "message": f"Broadcast enqueued for {project['name']}. Processing safely under rate limits.",
        "jobId": job_id,
        "totalRecipients": len(queue_items),
        "status": "queued",
        "priority": "low_queued",
        "rateLimitPacing": f"{BROADCAST_DELAY_SECONDS}s per email",
    })


@app.route("/api/broadcast/all", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def enqueue_all_projects_broadcast():
    """Global broadcast enqueued for all active subscribers across ALL projects.

    Requires MASTER_API_KEY.
    """
    if request.method == "GET":
        return fail("bad_request", "This endpoint requires a POST request with JSON payload: {'subject': '...', 'message': '...'}", 400)

    key = get_api_key_from_request()
    if not MASTER_API_KEY or key != MASTER_API_KEY:
        return fail("forbidden", "Master API key required for global multi-project broadcasts.", 403)

    data = request.get_json(silent=True) or {}
    subject_raw = str(data.get("subject", "")).strip()
    title = str(data.get("title") or subject_raw).strip()
    message = str(data.get("message", "")).strip()
    action_url = data.get("action_url")
    action_label = data.get("action_label")
    custom_header = data.get("custom_header")
    custom_footer = data.get("custom_footer")

    if not subject_raw or not message:
        return fail("invalid_parameters", "'subject' and 'message' are required.", 400)

    db = get_db()
    cursor = db.subscribers.find({"isSubscribed": True})
    seen_emails = set()
    recipients = []
    for doc in cursor:
        em = doc.get("email", "").lower().strip()
        if em and em not in seen_emails:
            seen_emails.add(em)
            recipients.append(em)

    if not recipients:
        return jsonify({
            "success": True,
            "message": "No active subscribers found across projects.",
            "jobId": None,
            "totalRecipients": 0,
        })

    job_id = f"job_global_{int(time.time())}_{secrets.token_hex(4)}"
    job_doc = {
        "_id": job_id,
        "projectId": "network",
        "projectName": SMTP_FROM_NAME or "Network Announcements",
        "subject": subject_raw,
        "title": title,
        "message": message,
        "actionUrl": action_url,
        "actionLabel": action_label,
        "customHeader": custom_header,
        "customFooter": custom_footer,
        "totalRecipients": len(recipients),
        "sentCount": 0,
        "failedCount": 0,
        "status": "queued",
        "createdAt": now(),
    }
    db.broadcast_jobs.insert_one(job_doc)

    queue_items = [
        {
            "_id": f"{job_id}:{em}",
            "jobId": job_id,
            "projectId": "network",
            "email": em,
            "status": "pending",
            "attempts": 0,
            "createdAt": now(),
        }
        for em in recipients
    ]
    if queue_items:
        db.broadcast_queue.insert_many(queue_items)

    threading.Thread(target=process_broadcast_queue_job, args=(job_id,), daemon=True).start()

    return jsonify({
        "success": True,
        "message": "Global multi-project broadcast enqueued. Processing safely under rate limits.",
        "jobId": job_id,
        "totalRecipients": len(queue_items),
        "status": "queued",
        "priority": "low_queued",
        "rateLimitPacing": f"{BROADCAST_DELAY_SECONDS}s per email",
    })


@app.route("/api/broadcast/status/<job_id>", methods=["GET", "OPTIONS"], strict_slashes=False)
def broadcast_job_status(job_id):
    """Checks progress of a broadcast job in the queue."""
    db = get_db()
    job = db.broadcast_jobs.find_one({"_id": job_id})
    if not job:
        return fail("not_found", f"Broadcast job '{job_id}' not found.", 404)

    total = job.get("totalRecipients", 0)
    sent = job.get("sentCount", 0)
    failed = job.get("failedCount", 0)
    progress_pct = round(((sent + failed) / total * 100), 1) if total > 0 else 100

    return jsonify({
        "success": True,
        "jobId": job_id,
        "status": job.get("status"),
        "totalRecipients": total,
        "sentCount": sent,
        "failedCount": failed,
        "progressPercent": progress_pct,
        "createdAt": job.get("createdAt"),
        "completedAt": job.get("completedAt"),
    })


@app.route("/api/queue/process", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def trigger_queue_process():
    """Manual or Cron trigger to process next pending broadcast jobs."""
    db = get_db()
    pending_job = db.broadcast_jobs.find_one({"status": {"$in": ["queued", "processing"]}})
    if not pending_job:
        return jsonify({"success": True, "message": "No pending broadcast jobs to process."})

    process_broadcast_queue_job(pending_job["_id"])
    return jsonify({"success": True, "message": f"Processed batch for job {pending_job['_id']}."})


# ------------------------------------------------------------------------------
# 7. Bring-Your-Own-SMTP (BYOS) Management
# ------------------------------------------------------------------------------
@app.route("/api/project/smtp", methods=["GET", "POST", "DELETE", "OPTIONS"], strict_slashes=False)
def manage_project_smtp():
    """Configures, checks, or clears custom SMTP credentials for a project."""
    project, err = resolve_project()
    if err:
        return err

    project_id = str(project["_id"])

    if request.method == "GET":
        custom = project.get("smtp", {})
        return jsonify({
            "success": True,
            "project": project["name"],
            "customSmtpEnabled": bool(custom.get("enabled")),
            "host": custom.get("host") or SMTP_HOST,
            "port": custom.get("port") or SMTP_PORT,
            "user": custom.get("user") or (SMTP_USER if not custom.get("enabled") else ""),
            "fromEmail": custom.get("fromEmail") or (SMTP_FROM_EMAIL if not custom.get("enabled") else ""),
            "replyTo": project.get("replyToEmail") or custom.get("replyTo") or "",
        })

    db = get_db()

    if request.method == "DELETE":
        db.projects.update_one({"_id": project_id}, {"$set": {"smtp": {"enabled": False}}})
        return jsonify({
            "success": True,
            "message": f"Custom SMTP removed for {project['name']}. Reverted to platform default SMTP.",
        })

    # POST: Configure and verify custom SMTP credentials
    data = request.get_json(silent=True) or {}
    host = str(data.get("host") or "smtp.gmail.com").strip()
    port = int(data.get("port", 465))
    use_ssl = bool(data.get("secure", True)) or port == 465
    user = str(data.get("user", "")).strip()
    password = str(data.get("password", "")).replace(" ", "")
    from_email = str(data.get("from_email") or user).strip()
    from_name = str(data.get("from_name") or project["name"]).strip()
    reply_to = str(data.get("reply_to") or from_email).strip()

    if not user or not password:
        return fail("invalid_credentials", "'user' (email) and 'password' (or app password) are required.", 400)

    # Test the SMTP credentials immediately before saving
    context = ssl.create_default_context()
    try:
        if use_ssl or port == 465:
            try:
                with smtplib.SMTP_SSL(host, port, context=context, timeout=10) as test_srv:
                    _smtp_login(test_srv, user, password)
            except (socket.timeout, OSError):
                # Fallback to 587
                with smtplib.SMTP(host, 587, timeout=10) as test_srv:
                    test_srv.ehlo()
                    test_srv.starttls(context=context)
                    test_srv.ehlo()
                    _smtp_login(test_srv, user, password)
        else:
            with smtplib.SMTP(host, port, timeout=10) as test_srv:
                test_srv.ehlo()
                test_srv.starttls(context=context)
                test_srv.ehlo()
                _smtp_login(test_srv, user, password)
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = auth_err.smtp_error.decode("utf-8", errors="ignore") if isinstance(getattr(auth_err, "smtp_error", None), bytes) else str(getattr(auth_err, "smtp_error", "") or auth_err or "Bad credentials")
        return fail("smtp_auth_failed", f"Authentication failed: {err_msg}. Check email and App Password.", 400)
    except Exception as e:
        return fail("smtp_connection_failed", f"Failed to connect to {host}:{port} — {e}", 400)

    smtp_doc = {
        "enabled": True,
        "host": host,
        "port": port,
        "secure": use_ssl,
        "user": user,
        "password": password,
        "fromEmail": from_email,
        "fromName": from_name,
        "replyTo": reply_to,
        "updatedAt": now(),
    }

    db.projects.update_one(
        {"_id": project_id},
        {"$set": {"smtp": smtp_doc, "replyToEmail": reply_to}},
        upsert=True,
    )

    return jsonify({
        "success": True,
        "message": f"Custom SMTP verified & saved for {project['name']}. Outgoing emails will now use these credentials.",
        "project": project["name"],
        "user": user,
        "fromEmail": from_email,
        "replyTo": reply_to,
    })


# ------------------------------------------------------------------------------
# 8. Unsubscribe & Resubscribe Handlers
# ------------------------------------------------------------------------------
@app.route("/api/unsubscribe", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def handle_unsubscribe():
    """One-click unsubscribe endpoint supporting both browser GET and RFC 8058 POST."""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        project_id = str(request.args.get("project") or data.get("project") or "").strip()
        email = str(request.args.get("email") or data.get("email") or "").strip().lower()
        sig = str(request.args.get("sig") or data.get("sig") or "").strip()
    else:
        project_id = str(request.args.get("project", "")).strip()
        email = str(request.args.get("email", "")).strip().lower()
        sig = str(request.args.get("sig", "")).strip()

    if not project_id or not email:
        return "<h3>Missing project or email parameter.</h3>", 400

    expected_sig = make_unsub_sig(project_id, email)
    if not hmac.compare_digest(expected_sig, sig):
        return "<h3>Invalid or expired unsubscribe link.</h3>", 403

    try:
        db = get_db()
        db.subscribers.update_one(
            {"_id": f"{project_id}:{email}"},
            {"$set": {"isSubscribed": False, "unsubscribedAt": now()}},
            upsert=True,
        )
    except Exception as e:
        app.logger.warning("Unsubscribe database record error: %s", e)

    if request.is_json:
        return jsonify({"success": True, "message": f"{email} unsubscribed from {project_id}."})

    resub_url = f"{(APP_URL or request.host_url).rstrip('/')}/api/resubscribe?project={project_id}&email={email}&sig={sig}"
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Unsubscribed from Broadcasts</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f6f9; display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 16px; color: #101828; }}
    .box {{ background: #fff; max-width: 440px; border-radius: 12px; padding: 32px 24px; text-align: center; border: 1px solid #d0d5dd; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
    .icon {{ width: 48px; height: 48px; line-height: 48px; border-radius: 50%; background: #f2f4f7; font-size: 20px; margin: 0 auto 16px; }}
    h2 {{ margin: 0 0 8px; font-size: 20px; }}
    p {{ color: #475467; font-size: 14px; line-height: 1.5; margin: 0 0 20px; }}
    .btn {{ display: inline-block; padding: 10px 20px; background: #1f3fd1; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; }}
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">✓</div>
    <h2>Unsubscribed from Broadcasts</h2>
    <p><strong>{escape(email)}</strong> has been unsubscribed from <strong>{escape(project_id)}</strong> announcements.<br><br>You will no longer receive broadcast updates. (Mandatory emails like verification codes and password resets will always be delivered, and using them will automatically reactivate your normal status).</p>
    <a href="{escape(resub_url)}" class="btn">Undo &amp; Re-subscribe</a>
  </div>
</body>
</html>"""


@app.route("/api/resubscribe", methods=["GET", "OPTIONS"], strict_slashes=False)
def handle_resubscribe():
    project_id = str(request.args.get("project", "")).strip()
    email = str(request.args.get("email", "")).strip().lower()
    sig = str(request.args.get("sig", "")).strip()

    if not project_id or not email:
        return "<h3>Missing project or email.</h3>", 400

    expected_sig = make_unsub_sig(project_id, email)
    if not hmac.compare_digest(expected_sig, sig):
        return "<h3>Invalid link.</h3>", 403

    try:
        db = get_db()
        db.subscribers.update_one(
            {"_id": f"{project_id}:{email}"},
            {"$set": {"isSubscribed": True, "unsubscribedAt": None}},
            upsert=True,
        )
    except Exception as e:
        app.logger.warning("Resubscribe database record error: %s", e)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Re-subscribed</title><style>body{{font-family:sans-serif;background:#f3f6f9;display:grid;place-items:center;min-height:100vh;margin:0;}}.box{{background:#fff;padding:32px;border-radius:12px;border:1px solid #d0d5dd;text-align:center;max-width:380px;}}h2{{color:#079455;margin-top:0;}}</style></head>
<body><div class="box"><h2>Re-subscribed!</h2><p>You have been re-subscribed to updates for <strong>{escape(project_id)}</strong>.</p></div></body></html>"""


# ------------------------------------------------------------------------------
# 9. Subscribers Listing
# ------------------------------------------------------------------------------
@app.route("/api/subscribers", methods=["GET", "OPTIONS"], strict_slashes=False)
def list_subscribers():
    project, err = resolve_project()
    if err:
        return err

    db = get_db()
    project_id = str(project["_id"])
    query = {"projectId": project_id} if not project.get("isMaster") else {}
    subscribers = list(db.subscribers.find(query, {"_id": 1, "email": 1, "name": 1, "isSubscribed": 1, "source": 1, "createdAt": 1}))

    return jsonify({
        "success": True,
        "project": project["name"],
        "count": len(subscribers),
        "subscribers": subscribers,
    })


# ------------------------------------------------------------------------------
# 10. Admin / Project Management (Requires MASTER_API_KEY)
# ------------------------------------------------------------------------------
@app.route("/api/admin/projects", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def handle_admin_projects():
    key = get_api_key_from_request()
    if not MASTER_API_KEY or key != MASTER_API_KEY:
        return fail("forbidden", "Master API key required.", 403)

    db = get_db()
    if request.method == "GET":
        projects = list(db.projects.find({}, {"_id": 1, "name": 1, "apiKey": 1, "fromName": 1, "replyToEmail": 1, "headerTitle": 1, "footerText": 1, "smtp.enabled": 1, "isActive": 1, "createdAt": 1}))
        return jsonify({"success": True, "projects": projects})

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return fail("invalid_name", "'name' is required for the project.", 400)

    slug = str(data.get("slug") or name.lower().replace(" ", "_")).strip()
    api_key = str(data.get("api_key") or f"sk_{slug}_{secrets.token_hex(12)}").strip()
    from_name = str(data.get("from_name") or name).strip()
    reply_to = str(data.get("reply_to") or f"support+{slug}@dhyey.cc").strip()
    header_title = str(data.get("header_title") or name).strip()
    footer_text = str(data.get("footer_text") or f"© {now().year} {name}. All rights reserved.").strip()

    existing = db.projects.find_one({"$or": [{"_id": slug}, {"apiKey": api_key}]})
    if existing:
        return fail("conflict", f"Project with ID '{slug}' or this API key already exists.", 409)

    doc = {
        "_id": slug,
        "name": name,
        "apiKey": api_key,
        "fromName": from_name,
        "replyToEmail": reply_to,
        "headerTitle": header_title,
        "footerText": footer_text,
        "smtp": {"enabled": False},
        "isActive": True,
        "createdAt": now(),
    }
    db.projects.insert_one(doc)

    return jsonify({
        "success": True,
        "message": f"Project '{name}' registered.",
        "project": doc,
    }), 201


@app.route("/api/admin/projects/<project_id>", methods=["DELETE", "OPTIONS"], strict_slashes=False)
def delete_project(project_id):
    key = get_api_key_from_request()
    if not MASTER_API_KEY or key != MASTER_API_KEY:
        return fail("forbidden", "Master API key required.", 403)

    db = get_db()
    res = db.projects.delete_one({"_id": project_id})
    if res.deleted_count == 0:
        return fail("not_found", "Project not found.", 404)

    return jsonify({"success": True, "message": f"Project '{project_id}' deleted."})


# ------------------------------------------------------------------------------
# Error Handlers & Root Static Serving
# ------------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_):
    return fail("not_found", "Unknown route.", 404)


@app.errorhandler(405)
def bad_method(e=None):
    valid_methods = list(getattr(e, "valid_methods", [])) if hasattr(e, "valid_methods") else []
    msg = f"HTTP method '{request.method}' is not allowed for {request.path}."
    if valid_methods:
        msg += f" Allowed methods: {', '.join(valid_methods)}."
    return fail("method_not_allowed", msg, 405, allowed_methods=valid_methods)


@app.errorhandler(413)
def too_large(_):
    return fail("too_large", "Request payload exceeds size limit.", 413)


@app.errorhandler(Exception)
def unexpected(exc):
    app.logger.exception(exc)
    return fail("server_error", "An unexpected server error occurred.", 500)


@app.route("/api/index", methods=["GET", "POST", "OPTIONS"], strict_slashes=False)
def vercel_entrypoint():
    """Fallback handler when /api/index is invoked directly without rewrite metadata."""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    if request.method == "GET":
        return jsonify({
            "service": "Personal OTP & Email Gateway",
            "status": "healthy",
            "endpoints": [
                "/api/send-otp",
                "/api/verify-otp",
                "/api/send-reset-password",
                "/api/send-greeting",
                "/api/send-mail",
                "/api/broadcast",
                "/api/project/smtp",
                "/api/subscribers",
            ],
        })

    data = request.get_json(silent=True) or {}
    if "otp" in data and "email" in data:
        return verify_otp()
    if "email" in data:
        return send_otp()

    return fail("bad_request", "POST to /api/index requires an action or payload. Use specific endpoints like /api/send-otp.", 400)


@app.route("/", methods=["GET", "OPTIONS"], strict_slashes=False)
def serve_index():
    return send_from_directory(ROOT, "index.html")


@app.route("/<path:path>", methods=["GET", "POST", "OPTIONS", "DELETE", "PUT"], strict_slashes=False)
def serve_static(path):
    if request.method in ("GET", "OPTIONS", "HEAD"):
        file_path = os.path.join(ROOT, path)
        if os.path.isfile(file_path):
            return send_from_directory(ROOT, path)
    return fail("not_found", f"Unknown route or resource '/{path}'.", 404)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(port=port, debug=True)
