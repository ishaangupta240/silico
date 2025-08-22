import os
import smtplib
from email.mime.text import MIMEText
from threading import Thread
from dotenv import load_dotenv
load_dotenv()

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER)


def _send_email_sync(to: str, subject: str, body: str):
    try:
        if not SMTP_USER or not SMTP_PASS:
            print(f"[DEV EMAIL] To: {to}\nSubject: {subject}\n\n{body}")
            return
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_FROM
        msg['To'] = to
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to], msg.as_string())
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send to {to}: {e}")


def send_email(to: str, subject: str, body: str):
    Thread(target=_send_email_sync, args=(to, subject, body), daemon=True).start()
