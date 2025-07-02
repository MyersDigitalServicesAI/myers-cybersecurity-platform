import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import logging

logger = logging.getLogger(__name__)

# --- Email Configuration (from environment variables) ---
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_API_KEY = os.environ.get("SMTP_API_KEY")
APP_URL = os.environ.get("APP_URL", "http://localhost:8501")

class EmailAutomation:
    def __init__(self):
        if not all([SENDER_EMAIL, SMTP_SERVER, SMTP_USER, SMTP_API_KEY]):
            logger.critical("Email sending environment variables not fully set. Email functions might fail.")
            # Not raising an error to allow the app to run, but logging it critically.
            self.configured = False
        else:
            self.configured = True

    def _send_email(self, to_email, subject, html_content):
        if not self.configured:
            logger.error("Email service is not configured. Skipping sending email.")
            return False, "Email service not configured."
        if not to_email:
            logger.error("Attempted to send email with no recipient email address.")
            return False, "No recipient email"
            
        msg = MIMEText(html_content, "html")
        msg["Subject"] = subject
        msg["From"] = formataddr(("Myers Cybersecurity", SENDER_EMAIL))
        msg["To"] = to_email

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_API_KEY)
                server.send_message(msg)
            logger.info(f"Email sent successfully to {to_email} for subject: '{subject}'")
            return True, ""
        except Exception as e:
            logger.error(f"Failed to send email to {to_email} (Subject: '{subject}'): {e}", exc_info=True)
            return False, str(e)

    # All other existing methods like send_welcome_email, etc. remain here...

    def send_welcome_email(self, user_details):
        subject = "Welcome to Myers Cybersecurity!"
        html = f"""
        <html><body>
            <p>Hello {user_details.get('first_name', 'User')},<br>
            Welcome to Myers Cybersecurity! We're excited to have you on board.</p>
            <p>You can log in to your dashboard here:<br>
            <a href="{APP_URL}">Login to Dashboard</a></p>
            <p>Sincerely,<br>The Myers Cybersecurity Team</p>
        </body></html>
        """
        self._send_email(user_details['email'], subject, html)

    def send_verification_email(self, to_email, user_name, verification_link):
        subject = "Verify your email address - Myers Cybersecurity"
        html = f"""
        <html><body>
            <p>Hello {user_name},<br>
            Thanks for signing up. Please verify your email by clicking the link below:<br>
            <a href="{verification_link}">{verification_link}</a><br><br>
            If you did not sign up, please ignore this email.</p>
            <p>Sincerely,<br>The Myers Cybersecurity Team</p>
        </body></html>
        """
        return self._send_email(to_email, subject, html)

    # ADDED: This method was missing
    def send_password_reset_email(self, to_email, reset_link):
        subject = "Reset Your Myers Cybersecurity Password"
        html = f"""
        <html><body>
            <p>Hello,<br>
            You requested a password reset. Please click the link below to set a new password:<br>
            <a href="{reset_link}">{reset_link}</a><br><br>
            If you did not request this, please ignore this email.</p>
            <p>Sincerely,<br>The Myers Cybersecurity Team</p>
        </body></html>
        """
        return self._send_email(to_email, subject, html)
        
    def send_admin_alert(self, message):
        admin_email = os.environ.get("SETUP_ADMIN_EMAIL")
        if admin_email:
            subject = "Admin Alert - Myers Cybersecurity"
            html = f"<html><body><p>This is an automated admin alert:</p><p><b>{message}</b></p></body></html>"
            self._send_email(admin_email, subject, html)

    # The rest of your EmailAutomation class and the EmailEventHandler class...
