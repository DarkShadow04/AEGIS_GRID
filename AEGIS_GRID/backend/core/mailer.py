"""
Mailer
Sends a scan report by email via user-configured SMTP (not a third-party
email API — one less key to manage, and works with any provider: Gmail
with an app password, Outlook, a personal mail server, etc.).
"""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

from core import secrets_store


def is_configured() -> bool:
    return bool(secrets_store.get_key("smtp_host") and secrets_store.get_key("smtp_user") and secrets_store.get_key("smtp_password"))


def send_report_email(to_email: str, subject: str, body_text: str, attachment_bytes: bytes = None, attachment_name: str = None) -> dict:
    if not is_configured():
        return {"error": "SMTP not configured. Add your mail server details in Settings."}

    host = secrets_store.get_key("smtp_host")
    port = int(secrets_store.get_key("smtp_port") or 587)
    user = secrets_store.get_key("smtp_user")
    password = secrets_store.get_key("smtp_password")
    from_addr = secrets_store.get_key("smtp_from") or user

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    if attachment_bytes and attachment_name:
        part = MIMEApplication(attachment_bytes, Name=attachment_name)
        part["Content-Disposition"] = f'attachment; filename="{attachment_name}"'
        msg.attach(part)

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(from_addr, [to_email], msg.as_string())
        return {"sent": True, "to": to_email}
    except smtplib.SMTPAuthenticationError:
        return {"error": "SMTP authentication failed — check username/password (Gmail etc. need an app password, not your account password)."}
    except (smtplib.SMTPException, OSError) as e:
        return {"error": f"Email send failed: {str(e)[:300]}"}
