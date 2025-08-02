   import os
import logging
from typing import Dict, Any

# --- Third-Party Imports ---
# Use the official SendGrid library for robust email sending.
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

class EmailAutomation:
    """
    Handles the direct sending of transactional emails using the SendGrid API.
    This class is the "transport layer" for emails.
    """
    def __init__(self):
        """
        Initializes the SendGrid API client.
        Raises ValueError if critical environment variables are missing.
        """
        self.sender_email = os.environ.get("SENDER_EMAIL")
        self.sendgrid_api_key = os.environ.get("SENDGRID_API_KEY")
        self.app_url = os.environ.get("APP_URL")

        if not all([self.sender_email, self.sendgrid_api_key, self.app_url]):
            logger.critical("FATAL: Email service environment variables (SENDER_EMAIL, SENDGRID_API_KEY, APP_URL) are not fully set.")
            raise ValueError("Email service configuration is incomplete.")
            
        self.sg_client = sendgrid.SendGridAPIClient(self.sendgrid_api_key)
        logger.info("EmailAutomation initialized with SendGrid API client.")

    def _send_email(self, recipient_email: str, subject: str, html_content: str) -> bool:
        """
        Internal method to construct and send an email using SendGrid.
        """
        if not recipient_email:
            logger.error("Attempted to send email with no recipient.")
            return False
            
        message = Mail(
            from_email=Email(self.sender_email, "Myers Cybersecurity"),
            to_emails=To(recipient_email),
            subject=subject,
            html_content=Content("text/html", html_content)
        )
        
        try:
            response = self.sg_client.send(message)
            # SendGrid returns a 202 status code for a successful send request.
            if 200 <= response.status_code < 300:
                logger.info(f"Email sent successfully to {recipient_email} with subject: '{subject}'")
                return True
            else:
                logger.error(f"Failed to send email via SendGrid. Status: {response.status_code}, Body: {response.body}")
                return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while sending email to {recipient_email}: {e}", exc_info=True)
            return False

    def send_welcome_email(self, user_details: Dict[str, Any]):
        """Sends a welcome email to a new user."""
        subject = "Welcome to Myers Cybersecurity!"
        html = f"""
        <p>Hi {user_details.get('first_name', 'there')},</p>
        <p>Welcome to the Myers Cybersecurity platform! We're excited to have you on board.</p>
        <p>You can log in to your dashboard here: <a href="{self.app_url}">{self.app_url}</a></p>
        <p>Thanks,<br>The MyersDigital Team</p>
        """
        self._send_email(user_details['email'], subject, html)

    def send_password_reset_email(self, recipient_email: str, reset_link: str):
        """Sends a password reset link to a user."""
        subject = "Your Password Reset Link for Myers Cybersecurity"
        html = f"""
        <p>Hello,</p>
        <p>You requested a password reset for your Myers Cybersecurity account. Please click the link below to set a new password. This link is valid for one hour.</p>
        <p><a href="{reset_link}">Reset Your Password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>Thanks,<br>The MyersDigital Team</p>
        """
        self._send_email(recipient_email, subject, html)

class EmailEventHandler:
    """
    Handles the business logic for triggering specific emails based on application events.
    This class is the "logic layer" for emails.
    """
    def __init__(self, security_core: 'SecurityCore', email_automation: EmailAutomation):
        self.security_core = security_core
        self.email_automation = email_automation
        logger.info("EmailEventHandler initialized.")

    def _get_user_details(self, user_id: str) -> Dict[str, Any]:
        """Helper to fetch user details for an email."""
        return self.security_core.get_user_by_id(user_id)

    def handle_payment_successful(self, user_id: str):
        user = self._get_user_details(user_id)
        if user:
            # Re-implementing the email logic here for clarity, though it could call EmailAutomation
            subject = "Your MyersCybersecurity Subscription is Active!"
            body = f"Hi {user.get('first_name', 'there')},\n\nThank you for your payment. Your subscription is now active."
            self.email_automation._send_email(user['email'], subject, body)

    def handle_payment_failed(self, user_id: str, invoice_details: Dict[str, Any]):
        user = self._get_user_details(user_id)
        if user:
            subject = "Action Required: Your Payment Failed"
            body = f"Hi {user.get('first_name', 'there')},\n\nWe were unable to process your payment. Please update your payment information here: {invoice_details.get('invoice_url', self.email_automation.app_url)}"
            self.email_automation._send_email(user['email'], subject, body)

    def handle_subscription_cancelled(self, user_id: str):
        user = self._get_user_details(user_id)
        if user:
            subject = "Your Subscription Has Been Cancelled"
            body = f"Hi {user.get('first_name', 'there')},\n\nThis email confirms that your subscription has been cancelled."
            self.email_automation._send_email(user['email'], subject, body)
