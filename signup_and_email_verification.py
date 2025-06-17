# email_automation.py
import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import logging


logger = logging.getLogger(__name__)

# --- Email Configuration (from environment variables) ---
SENDER_EMAIL = os.environ["SENDER_EMAIL"]"
SMTP_SERVER = os.environ["SMTP_SERVER"]"
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))"
SMTP_USER = os.environ["SMTP_USER"]"
SMTP_API_KEY = os.environ["SMTP_API_KEY"]"
APP_URL = os.environ["APP_URL"]

class EmailAutomation:
    def __init__(self):
        if not SENDER_EMAIL or not SMTP_SERVER or not SMTP_API_KEY:"
            logger.critical("Email sending environment variables (SENDER_EMAIL, SMTP_SERVER, SMTP_API_KEY) not fully set. Email functions might fail.")"
            raise ValueError("Email configuration is incomplete.")

    def _send_email(self, to_email, subject, html_content):
        if not to_email:"
            logger.error("Attempted to send email with no recipient email address.")"
            return False, "No recipient email""
        msg = MIMEText(html_content, "html")"
        msg["Subject"] = subject"
        msg["From"] = formataddr(("Myers Cybersecurity", SENDER_EMAIL))"
        msg["To"] = to_email

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_API_KEY)
                server.send_message(msg)"
            logger.info(f"Email sent successfully to {to_email} for subject: '{subject}'")"
            return True, ""
        except Exception as e:"
            logger.error(f"Failed to send email to {to_email} (Subject: '{subject}'): {e}", exc_info=True)
            return False, str(e)

    def send_welcome_email(self, user_iddetails):"
        subject = "Welcome to Myers Cybersecurity!""
        html = f"""\
        <html>
            <body>"
                <p>Hello {user_iddetails.get('first_name', 'User')},<br>'
                Welcome to Myers Cybersecurity! We're excited to have you on board.</p>
                <p>You can log in to your dashboard here:<br>'
                <a href="{APP_URL}/login">Login to Dashboard</a></p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>"
        """"
        self._send_email(user_iddetails['email'], subject, html)

    def send_verification_email(self, to_email, user_idname, verification_link):'
        subject = "Verify your email address - Myers Cybersecurity""
        html = f"""\
        <html>
            <body>
                <p>Hello {user_idname},<br>
                Thanks for signing up for Myers Cybersecurity.<br>
                Please verify your email by clicking the link below:<br>"
                <a href="{verification_link}">{verification_link}</a>
                <br><br>
                If you did not sign up, please ignore this email.
                </p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>"
        """
        return self._send_email(to_email, subject, html)

    def send_payment_successful_email(self, user_iddetails):"
        subject = "Payment Successful - Your Myers Cybersecurity Subscription""
        html = f"""\
        <html>
            <body>"
                <p>Hello {user_iddetails.get('first_name', 'User')},<br>
                Your recent payment for Myers Cybersecurity was successful! 🎉<br>'
                Thank you for being a valued subscriber. Your {user_iddetails.get('plan', 'Professional').title()} plan is now active.<br>
                </p>
                <p>You can manage your subscription and view invoices in your dashboard:<br>'
                <a href="{APP_URL}/dashboard">Go to Dashboard</a></p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>"
        """"
        self._send_email(user_iddetails['email'], subject, html)

    def send_payment_failed_email(self, user_iddetails, invoice_details):'
        subject = "Action Required: Your Myers Cybersecurity Payment Failed""
        html = f"""\
        <html>
            <body>"
                <p>Hello {user_iddetails.get('first_name', 'User')},<br>
                We regret to inform you that your recent payment for Myers Cybersecurity failed.'
                Invoice amount: ${invoice_details.get('amount', 'N/A'):.2f}, dated: {invoice_details.get('date', 'N/A')}.<br>
                </p>
                <p>Please update your payment method to avoid service interruption:<br>'
                <a href="{invoice_details.get('invoice_url', f'{APP_URL}/dashboard')}">View Invoice & Update Payment</a></p>
                <p>If you have any questions, please contact our support team.</p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>"
        """"
        self._send_email(user_iddetails['email'], subject, html)

    def send_subscription_cancelled_email(self, user_iddetails):'
        subject = "Your Myers Cybersecurity Subscription Has Been Cancelled""
        html = f"""\
        <html>
            <body>"
                <p>Hello {user_iddetails.get('first_name', 'User')},<br>
                This email confirms that your Myers Cybersecurity subscription has been cancelled.<br>
                </p>'
                <p>We're sorry to see you go! If you have any feedback or wish to reactivate your subscription, please contact us.</p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>'
        """"
        self._send_email(user_iddetails['email'], subject, html)


class EmailEventHandler:
    def __init__(self, security_core_instance, email_automation_instance):
        self.security_core = security_core_instance
        self.email_automation = email_automation_instance

    def _get_user_iddetails_for_email(self, user_idid):
        user_iddetails = self.security_core.get_user_iddetails(user_idid)
        if not user_iddetails:'
            logger.error(f"Could not retrieve user details for ID {user_idid} for email sending.")
            return None"
        user_iddetails.setdefault('email', 'unknown@example.com')'
        user_iddetails.setdefault('first_name', 'Valued Customer')'
        user_iddetails.setdefault('plan', 'Unknown Plan')
        return user_iddetails

    def handle_payment_successful(self, user_idid):
        user_iddetails = self._get_user_iddetails_for_email(user_idid)
        if user_iddetails:'
            logger.info(f"Triggering payment successful email for {user_iddetails.get('email')}")
            self.email_automation.send_payment_successful_email(user_iddetails)

    def handle_payment_failed(self, user_idid, invoice_details):
        user_iddetails = self._get_user_iddetails_for_email(user_idid)
        if user_iddetails:"
            logger.info(f"Triggering payment failed email for {user_iddetails.get('email')}")
            self.email_automation.send_payment_failed_email(user_iddetails, invoice_details)

    def handle_subscription_cancelled(self, user_idid):
        user_iddetails = self._get_user_iddetails_for_email(user_idid)
        if user_iddetails:"
            logger.info(f"Triggering subscription cancelled email for {user_iddetails.get('email')}")
            self.email_automation.send_subscription_cancelled_email(user_iddetails)

    def handle_welcome_email(self, user_idid):
        user_iddetails = self._get_user_iddetails_for_email(user_idid)
        if user_iddetails:"
            logger.info(f"Triggering welcome email for {user_iddetails.get('email')}")
            self.email_automation.send_welcome_email(user_iddetails)"
