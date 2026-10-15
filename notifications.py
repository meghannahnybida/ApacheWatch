"""Durable email delivery for ApacheWatch, independent of dashboard requests."""

import json
import os
import re
import smtplib
import sqlite3
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from urllib.parse import urlparse

_UNSET = object()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def init_notification_storage(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=15) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS email_preferences (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL,
                severity TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_recipient_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                recipients_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                recipients TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                next_attempt_at TEXT NOT NULL,
                sent_at TEXT,
                lease_until TEXT,
                claim_token TEXT,
                error_code TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_email_pending_item
                ON email_outbox(item_id)
                WHERE kind = 'alert' AND status IN ('pending', 'sending');
            CREATE INDEX IF NOT EXISTS idx_email_delivery
                ON email_outbox(status, next_attempt_at);
            CREATE TABLE IF NOT EXISTS monitoring_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_checked_at TEXT,
                last_success_at TEXT,
                error TEXT
            );
        """)


def valid_email(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[^@\s<>,;:"]+@[^@\s<>,;:"]+\.[^@\s<>,;:"]+', value))


def email_settings(config_data, recipients=None):
    email = config_data.get("notifications", {}).get("email", {})
    smtp = email.get("smtp", {})
    username = os.environ.get("APACHEWATCH_SMTP_USERNAME", smtp.get("username", ""))
    settings = {
        "enabled": bool(email.get("enabled", False)),
        "severity": "all" if email.get("severity") == "all" else "critical",
        "recipients": email.get("recipients", []) if recipients is None else recipients,
        "host": os.environ.get("APACHEWATCH_SMTP_HOST", smtp.get("host", "")),
        "security": os.environ.get("APACHEWATCH_SMTP_SECURITY", smtp.get("security", "starttls")),
        "username": username,
        "password": os.environ.get("APACHEWATCH_SMTP_PASSWORD", ""),
        "sender": os.environ.get("APACHEWATCH_EMAIL_FROM", email.get("sender", "")) or username,
        "public_url": os.environ.get("APACHEWATCH_PUBLIC_URL", email.get("dashboard_url", "")),
    }
    if isinstance(settings["recipients"], str):
        settings["recipients"] = [settings["recipients"]]
    missing = []
    if not settings["host"]:
        missing.append("SMTP host")
    if not valid_email(settings["sender"]):
        missing.append("sender address")
    if not isinstance(settings["recipients"], list) or not settings["recipients"] or not all(valid_email(value) for value in settings["recipients"]):
        missing.append("recipient address")
    if bool(username) != bool(settings["password"]):
        missing.append("SMTP username/password")
    if settings["security"] not in {"starttls", "ssl"}:
        missing.append("SMTP security (starttls or ssl)")
    try:
        settings["port"] = int(os.environ.get("APACHEWATCH_SMTP_PORT", smtp.get("port", 465 if settings["security"] == "ssl" else 587)))
        if not 1 <= settings["port"] <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        settings["port"] = 587
        missing.append("SMTP port")
    settings["configured"] = not missing
    settings["missing"] = missing
    return settings


def preferences(config_data):
    init_notification_storage(config_data["database"])
    with sqlite3.connect(config_data["database"]) as conn:
        row = conn.execute("SELECT enabled, severity FROM email_preferences WHERE id = 1").fetchone()
        recipients = conn.execute("SELECT recipients_json FROM email_recipient_settings WHERE id = 1").fetchone()
    settings = email_settings(config_data, json.loads(recipients[0]) if recipients else None)
    if row:
        settings["enabled"], settings["severity"] = bool(row[0]), row[1]
    return settings


def update_preferences(config_data, enabled=_UNSET, severity=_UNSET, recipients=_UNSET):
    if ((enabled is not _UNSET and not isinstance(enabled, bool))
            or (severity is not _UNSET and (not isinstance(severity, str) or severity not in {"critical", "all"}))):
        raise ValueError("enabled must be a boolean and severity must be critical or all")
    if recipients is not _UNSET:
        if not isinstance(recipients, list) or len(recipients) > 20:
            raise ValueError("Provide up to 20 email recipients.")
        cleaned = []
        seen = set()
        for address in recipients:
            if not isinstance(address, str) or len(address.strip()) > 254 or not valid_email(address.strip()):
                raise ValueError("Enter a valid email address for each recipient.")
            address = address.strip()
            if address.casefold() not in seen:
                cleaned.append(address)
                seen.add(address.casefold())
        recipients = cleaned
    init_notification_storage(config_data["database"])
    defaults = email_settings(config_data)
    with sqlite3.connect(config_data["database"], timeout=15) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT enabled, severity FROM email_preferences WHERE id = 1").fetchone()
        current_enabled, current_severity = row if row else (defaults["enabled"], defaults["severity"])
        conn.execute("INSERT OR REPLACE INTO email_preferences(id, enabled, severity) VALUES(1, ?, ?)", (
            int(current_enabled if enabled is _UNSET else enabled),
            current_severity if severity is _UNSET else severity,
        ))
        if recipients is not _UNSET:
            conn.execute("INSERT OR REPLACE INTO email_recipient_settings(id, recipients_json) VALUES(1, ?)", (json.dumps(recipients),))
            # Waiting emails follow the current recipient list, including removals.
            conn.execute("UPDATE email_outbox SET recipients = ? WHERE status = 'pending'", (json.dumps(recipients),))


def public_status(config_data):
    settings = preferences(config_data)
    with sqlite3.connect(config_data["database"]) as conn:
        sent_at = conn.execute("SELECT MAX(sent_at) FROM email_outbox WHERE status = 'sent'").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM email_outbox WHERE status IN ('pending', 'sending')").fetchone()[0]
        last_error = conn.execute("SELECT error_code FROM email_outbox ORDER BY id DESC LIMIT 1").fetchone()
        monitor = conn.execute("SELECT last_checked_at, last_success_at, error FROM monitoring_status WHERE id = 1").fetchone()
        test = conn.execute("SELECT id, status, sent_at FROM email_outbox WHERE kind = 'test' ORDER BY id DESC LIMIT 1").fetchone()
    try:
        interval = max(10, min(3600, int(config_data.get("monitoring", {}).get("interval_seconds", 60))))
    except (TypeError, ValueError):
        interval = 60
    monitor_active = bool(monitor and monitor[0] and (utcnow() - datetime.fromisoformat(monitor[0])).total_seconds() <= max(120, interval * 3))
    return {
        "enabled": settings["enabled"], "severity": settings["severity"],
        "recipients": settings["recipients"], "configured": settings["configured"],
        "missing": settings["missing"], "pending": pending,
        "last_sent_at": sent_at + "Z" if sent_at else None,
        "delivery_error": bool(last_error and last_error[0]),
        "last_check_at": monitor[1] + "Z" if monitor and monitor[1] else None,
        "monitor_error": monitor[2] if monitor else None,
        "interval_seconds": interval, "monitoring_active": monitor_active,
        "test": {"id": test[0], "status": test[1], "sent_at": test[2] + "Z" if test[2] else None} if test else None,
    }


def alert_message(config_data, item, now):
    server = config_data.get("server_name", "Apache server")
    subject = f"[ApacheWatch] {item['severity'].capitalize()}: {item['title']} ({server})"
    body = f"ApacheWatch detected a finding on {server}.\n\n{item['title']}\n{item['summary']}\n\nSeverity: {item['severity']}\nSource: {item['source']}\nOccurrences: {item['occurrence_count']}\nDetected at: {now.isoformat()} UTC\n"
    url = email_settings(config_data)["public_url"].rstrip("/")
    if urlparse(url).scheme in {"http", "https"} and urlparse(url).netloc:
        body += f"\nReview in Action Center: {url}/#actions\n"
    body += "\nResolve, dismiss, or snooze this finding in Action Center to stop further emails."
    return subject, body


def queue_alerts(config_data, items, now=None):
    settings = preferences(config_data)
    if not settings["enabled"] or not settings["configured"]:
        return 0
    now = now or utcnow()
    # Even a zero alert-history cooldown must not create an email every minute.
    try:
        cooldown = max(5, float(config_data.get("alerts", {}).get("cooldown_minutes", 30)))
    except (TypeError, ValueError):
        cooldown = 30
    cutoff = (now - timedelta(minutes=cooldown)).isoformat()
    queued = 0
    with sqlite3.connect(config_data["database"], timeout=15) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for item in items:
            if not item.get("currently_observed") or item["status"] not in {"new", "acknowledged"}:
                continue
            if settings["severity"] == "critical" and item["severity"] != "critical":
                continue
            if conn.execute("SELECT 1 FROM email_outbox WHERE item_id = ? AND kind = 'alert' AND (status IN ('pending', 'sending') OR (status = 'sent' AND sent_at >= ?) OR (status = 'failed' AND created_at >= ?)) LIMIT 1", (item["id"], cutoff, cutoff)).fetchone():
                continue
            subject, body = alert_message(config_data, item, now)
            conn.execute("INSERT INTO email_outbox(item_id, kind, subject, body, recipients, created_at, next_attempt_at) VALUES (?, 'alert', ?, ?, ?, ?, ?)", (item["id"], subject, body, json.dumps(settings["recipients"]), now.isoformat(), now.isoformat()))
            queued += 1
    return queued


def queue_test(config_data, now=None):
    settings = preferences(config_data)
    if not settings["configured"]:
        raise ValueError("Connect a sender account before sending a test email.")
    now = now or utcnow()
    with sqlite3.connect(config_data["database"], timeout=15) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM email_outbox WHERE kind = 'test' AND created_at >= ? LIMIT 1", ((now - timedelta(minutes=1)).isoformat(),)).fetchone():
            raise ValueError("Please wait a minute before sending another test email.")
        cursor = conn.execute("INSERT INTO email_outbox(kind, subject, body, recipients, created_at, next_attempt_at) VALUES ('test', ?, ?, ?, ?, ?)", (f"[ApacheWatch] Test email from {config_data.get('server_name', 'your server')}", "This is a test email from ApacheWatch. Your email delivery connection is working.\n", json.dumps(settings["recipients"]), now.isoformat(), now.isoformat()))
        return cursor.lastrowid


def send_email(settings, job):
    message = EmailMessage()
    message["From"] = settings["sender"]
    recipients = json.loads(job["recipients"])
    message["To"] = ", ".join(recipients)
    # Header injection is rejected by EmailMessage instead of changing recipients.
    message["Subject"] = job["subject"].replace("\r", " ").replace("\n", " ")
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = f"<apachewatch-{job['id']}@{settings['sender'].split('@')[-1]}>"
    message.set_content(job["body"])
    context = ssl.create_default_context()
    if settings["security"] == "ssl":
        transport = smtplib.SMTP_SSL(settings["host"], settings["port"], timeout=15, context=context)
    else:
        transport = smtplib.SMTP(settings["host"], settings["port"], timeout=15)
    with transport as smtp:
        smtp.ehlo()
        if settings["security"] == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        if settings["username"]:
            smtp.login(settings["username"], settings["password"])
        refused = smtp.send_message(message, from_addr=settings["sender"], to_addrs=recipients)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def deliver_pending(config_data, now=None, limit=10, job_id=None):
    now = now or utcnow()
    result = {"sent": 0, "failed": 0}
    for _ in range(limit):
        settings = preferences(config_data)
        if not settings["configured"]:
            break
        with sqlite3.connect(config_data["database"], timeout=15) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM email_outbox WHERE ((status = 'pending' AND next_attempt_at <= ?) OR (status = 'sending' AND lease_until <= ?)) AND (? IS NULL OR id = ?) ORDER BY id LIMIT 1", (now.isoformat(), now.isoformat(), job_id, job_id)).fetchone()
            if not row:
                break
            job = dict(row)
            job["recipients"] = json.dumps(settings["recipients"])
            if job["kind"] == "alert":
                item = conn.execute("SELECT status, currently_observed, severity FROM action_items WHERE id = ?", (job["item_id"],)).fetchone()
                if not settings["enabled"] or not item or item["status"] not in {"new", "acknowledged"} or not item["currently_observed"] or (settings["severity"] == "critical" and item["severity"] != "critical"):
                    conn.execute("UPDATE email_outbox SET status = 'cancelled', claim_token = NULL, lease_until = NULL WHERE id = ?", (job["id"],))
                    continue
            token = uuid.uuid4().hex
            conn.execute("UPDATE email_outbox SET status = 'sending', attempts = attempts + 1, claim_token = ?, lease_until = ? WHERE id = ?", (token, (now + timedelta(minutes=2)).isoformat(), job["id"]))
            job["attempts"] += 1
        try:
            send_email(settings, job)
        except (smtplib.SMTPException, OSError, ValueError) as error:
            # SMTP responses may include credentials or private server details. Never store them.
            code = "authentication" if isinstance(error, smtplib.SMTPAuthenticationError) else "delivery"
            status = "failed" if job["attempts"] >= 5 else "pending"
            delay = min(60, 2 ** (job["attempts"] - 1))
            with sqlite3.connect(config_data["database"]) as conn:
                conn.execute("UPDATE email_outbox SET status = ?, next_attempt_at = ?, error_code = ?, lease_until = NULL, claim_token = NULL WHERE id = ? AND claim_token = ?", (status, (now + timedelta(minutes=delay)).isoformat(), code, job["id"], token))
            result["failed"] += 1
        else:
            with sqlite3.connect(config_data["database"]) as conn:
                conn.execute("UPDATE email_outbox SET status = 'sent', sent_at = ?, error_code = NULL, lease_until = NULL, claim_token = NULL WHERE id = ? AND claim_token = ?", (now.isoformat(), job["id"], token))
            result["sent"] += 1
    return result


def record_monitor_check(config_data, error=None):
    init_notification_storage(config_data["database"])
    now = utcnow().isoformat()
    with sqlite3.connect(config_data["database"]) as conn:
        conn.execute("INSERT INTO monitoring_status(id, last_checked_at, last_success_at, error) VALUES(1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET last_checked_at = excluded.last_checked_at, last_success_at = COALESCE(excluded.last_success_at, monitoring_status.last_success_at), error = excluded.error", (now, None if error else now, error))
