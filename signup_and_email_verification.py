import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import logging

logger = logging.getLogger(__name__)

# --- Email Configuration (from environment variables) ---
# Using .get() for safer environment variable access
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_API_KEY = os.environ.get("SMTP_API_KEY")
APP_URL = os.environ.get("APP_URL")

class EmailAutomation:
    def __init__(self):
        if not all([SENDER_EMAIL, SMTP_SERVER, SMTP_API_KEY, APP_URL]): # Ensure all critical env vars are set
            logger.critical("Email sending environment variables (SENDER_EMAIL, SMTP_SERVER, SMTP_API_KEY, APP_URL) not fully set. Email functions might fail.")
            raise ValueError("Email configuration is incomplete. Please ensure all required environment variables are set.")

    def _send_email(self, to_email: str, subject: str, html_content: str) -> tuple[bool, str]:
        """
        Internal method to send an email.
        Args:
            to_email (str): Recipient's email address.
            subject (str): Email subject.
            html_content (str): HTML content of the email.
        Returns:
            tuple[bool, str]: (True, "") on success, (False, error_message) on failure.
        """
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

    def send_welcome_email(self, user_details: dict):
        """Sends a welcome email to a new user."""
        subject = "Welcome to Myers Cybersecurity!"
        html = f"""\
        <html>
            <body>
                <p>Hello {user_details.get('first_name', 'User')},<br>
                Welcome to Myers Cybersecurity! We're excited to have you on board.</p>
                <p>You can log in to your dashboard here:<br>
                <a href="{APP_URL}/login">Login to Dashboard</a></p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>
        """
        self._send_email(user_details['email'], subject, html)

    def send_verification_email(self, to_email: str, user_name: str, verification_link: str):
        """Sends an email verification link to the user."""
        subject = "Verify your email address - Myers Cybersecurity"
        html = f"""\
        <html>
            <body>
                <p>Hello {user_name},<br>
                Thanks for signing up for Myers Cybersecurity.<br>
                Please verify your email by clicking the link below:<br>
                <a href="{verification_link}">{verification_link}</a>
                <br><br>
                If you did not sign up, please ignore this email.
                </p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>
        """
        return self._send_email(to_email, subject, html)

    def send_payment_successful_email(self, user_details: dict):
        """Sends a payment successful notification email."""
        subject = "Payment Successful - Your Myers Cybersecurity Subscription"
        html = f"""\
        <html>
            <body>
                <p>Hello {user_details.get('first_name', 'User')},<br>
                Your recent payment for Myers Cybersecurity was successful! 🎉<br>
                Thank you for being a valued subscriber. Your {user_details.get('plan', 'Professional').title()} plan is now active.<br>
                </p>
                <p>You can manage your subscription and view invoices in your dashboard:<br>
                <a href="{APP_URL}/dashboard">Go to Dashboard</a></p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>
        """
        self._send_email(user_details['email'], subject, html)

    def send_payment_failed_email(self, user_details: dict, invoice_details: dict):
        """Sends a payment failed notification email."""
        subject = "Action Required: Your Myers Cybersecurity Payment Failed"
        html = f"""\
        <html>
            <body>
                <p>Hello {user_details.get('first_name', 'User')},<br>
                We regret to inform you that your recent payment for Myers Cybersecurity failed.
                Invoice amount: ${invoice_details.get('amount', 'N/A'):.2f}, dated: {invoice_details.get('date', 'N/A')}.<br>
                </p>
                <p>Please update your payment method to avoid service interruption:<br>
                <a href="{invoice_details.get('invoice_url', f'{APP_URL}/dashboard')}">View Invoice & Update Payment</a></p>
                <p>If you have any questions, please contact our support team.</p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>
        """
        self._send_email(user_details['email'], subject, html)

    def send_subscription_cancelled_email(self, user_details: dict):
        """Sends a subscription cancellation confirmation email."""
        subject = "Your Myers Cybersecurity Subscription Has Been Cancelled"
        html = f"""\
        <html>
            <body>
                <p>Hello {user_details.get('first_name', 'User')},<br>
                This email confirms that your Myers Cybersecurity subscription has been cancelled.<br>
                </p>
                <p>We're sorry to see you go! If you have any feedback or wish to reactivate your subscription, please contact us.</p>
                <p>Sincerely,<br>
                The Myers Cybersecurity Team</p>
            </body>
        </html>
        """
        self._send_email(user_details['email'], subject, html)


class EmailEventHandler:
    """
    Handles various email-related events by retrieving user details and
    dispatching to the EmailAutomation class.
    """
    def __init__(self, security_core_instance, email_automation_instance):
        self.security_core = security_core_instance
        self.email_automation = email_automation_instance

    def _get_user_details_for_email(self, user_id: str) -> dict | None:
        """
        Retrieves user details from SecurityCore for email sending.
        Standardized user_id parameter.
        """
        # Corrected method call from get_user_iddetails to get_user_by_id
        user_details = self.security_core.get_user_by_id(user_id)
        if not user_details:
            logger.error(f"Could not retrieve user details for ID {user_id} for email sending.")
            return None
        
        # Ensure essential keys are present, providing defaults if missing
        user_details.setdefault('email', 'unknown@example.com')
        user_details.setdefault('first_name', 'Valued Customer')
        user_details.setdefault('plan', 'Unknown Plan')
        return user_details

    def handle_payment_successful(self, user_id: str):
        """Handles the event of a successful payment, triggering an email."""
        user_details = self._get_user_details_for_email(user_id)
        if user_details:
            logger.info(f"Triggering payment successful email for {user_details.get('email')}")
            self.email_automation.send_payment_successful_email(user_details)

    def handle_payment_failed(self, user_id: str, invoice_details: dict):
        """Handles the event of a failed payment, triggering an email."""
        user_details = self._get_user_details_for_email(user_id)
        if user_details:
            logger.info(f"Triggering payment failed email for {user_details.get('email')}")
            self.email_automation.send_payment_failed_email(user_details, invoice_details)

    def handle_subscription_cancelled(self, user_id: str):
        """Handles the event of a subscription cancellation, triggering an email."""
        user_details = self._get_user_details_for_email(user_id)
        if user_details:
            logger.info(f"Triggering subscription cancelled email for {user_details.get('email')}")
            self.email_automation.send_subscription_cancelled_email(user_details)

    def handle_welcome_email(self, user_id: str):
        """Handles the event of a new user welcome, triggering an email."""
        user_details = self._get_user_details_for_email(user_id)
        if user_details:
            logger.info(f"Triggering welcome email for {user_details.get('email')}")
            self.email_automation.send_welcome_email(user_details)

