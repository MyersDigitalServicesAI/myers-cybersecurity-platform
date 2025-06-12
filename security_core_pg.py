import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any # Use Any for more flexible type hinting
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Personalization, To, From, Subject, HtmlContent, PlainTextContent

# Import the centralized Supabase client
from src.config.supabase_client import supabase, supabase_admin # Adjust path as needed

# --- MOCK SECURITY CORE FOR DEMONSTRATION ---
# In your actual application, this class would have real methods
# to interact with your Supabase database using the 'supabase' client.
class MockSecurityCore:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("MockSecurityCore")

    def get_user_details(self, user_id: str) -> Dict[str, Any] | None:
        """
        Mocks fetching user details from Supabase.
        In a real scenario, this would query the 'users' table using the 'supabase' client.
        """
        self.logger.info(f"Mocking user details fetch for user_id: {user_id}")
        try:
            # This is where your real implementation would query Supabase
            # using the 'supabase' client from supabase_client.py
            response = supabase.table("users").select("*").eq("id", user_id).single().execute()
            if response.data:
                return response.data
            else:
                self.logger.warning(f"No user found with ID: {user_id}")
                return None
        except Exception as e:
            self.logger.error(f"Error fetching user details for {user_id}: {e}")
            return None

# --- END MOCK ---


class EmailAutomation:
    def __init__(self, security_core: Any): # Type hint with Any for flexibility
        self.security_core = security_core
        self.sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
        self.from_email = os.getenv('FROM_EMAIL', 'noreply@myerscybersecurity.com')
        self.company_name = "Myers Cybersecurity"
        # Get the domain from environment variables for dynamic link generation
        self.app_domain = os.getenv('DOMAIN', 'https://myers-cybersecurity.onrender.com')

        if self.sendgrid_api_key:
            self.sg = SendGridAPIClient(api_key=self.sendgrid_api_key)
        else:
            self.sg = None
            logging.error("SENDGRID_API_KEY not found. Email sending will be disabled.")

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def send_email(self, to_email: str, subject: str, html_content: str, plain_content: str = "") -> bool:
        if not self.sg:
            self.logger.error(f"SendGrid client not configured. Cannot send email to {to_email}.")
            return False

        if not to_email:
            self.logger.error(f"Attempted to send email with empty 'to_email' for subject: {subject}")
            return False

        try:
            # Ensure proper email address format
            from_addr = From(self.from_email, self.company_name)
            to_addr = To(to_email) # SendGrid handles basic email validation

            mail = Mail(
                from_email=from_addr,
                to_emails=to_addr,
                subject=Subject(subject),
                html_content=HtmlContent(html_content)
            )
            if plain_content:
                mail.plain_text_content = PlainTextContent(plain_content)

            # SendGrid API call
            response = self.sg.send(mail)
            if response.status_code == 202:
                self.logger.info(f"Email sent successfully to {to_email} with subject: {subject}")
                return True
            else:
                self.logger.error(f"Failed to send email to {to_email}. Status: {response.status_code}, Body: {response.body}, Headers: {response.headers}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to send email to {to_email} due to exception: {e}", exc_info=True)
            return False

    def send_welcome_email(self, user_id: str, user_details: Dict) -> bool:
        subject = f"Welcome to {self.company_name} - Your Cybersecurity Journey Begins"
        # Ensure user_details contains 'email'
        if not user_details.get('email'):
            self.logger.error(f"Cannot send welcome email: user_details missing email for user_id {user_id}")
            return False

        # Use app_domain for all links
        trial_token = user_details.get("trial_token", "default_token") # Provide a fallback
        dashboard_link = f"{self.app_domain}/activate?token={trial_token}"

        html_content = f"""
        <html>
        <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
            .content {{ padding: 30px; }}
            .button {{ background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            .features {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .footer {{ background: #f1f1f1; padding: 20px; text-align: center; font-size: 12px; }}
        </style>
        </head>
        <body>
            <div class="header">
                <h1>Welcome to {self.company_name}!</h1>
                <p>Enterprise Cybersecurity Made Simple</p>
            </div>

            <div class="content">
                <h2>Hello {user_details.get('first_name', 'there')}!</h2>
                <p>Thank you for joining {self.company_name}. Your 30-day free trial has started, giving you full access to our enterprise cybersecurity platform.</p>

                <div class="features">
                    <h3>Your {user_details.get('plan', 'Professional').title()} Plan Includes:</h3>
                    <ul>
                        <li>🔐 Encrypted API key management</li>
                        <li>🛡️ Real-time threat detection</li>
                        <li>📊 Advanced security analytics</li>
                        <li>🚨 24/7 security monitoring</li>
                        <li>📞 Priority customer support</li>
                    </ul>
                </div>

                <p><strong>Special Offer:</strong> Convert to a paid plan within 15 days and get <strong>25% off</strong> your first year!</p>
                <a href="{dashboard_link}" class="button">Activate Your Trial</a>

                <h3>Next Steps:</h3>
                <ol>
                    <li>Add your first API keys for monitoring</li>
                    <li>Review your security analytics dashboard</li>
                    <li>Configure threat detection alerts</li>
                    <li>Explore our advanced features</li>
                </ol>

                <p>Need help getting started? Our support team is here to assist you.</p>
            </div>

            <div class="footer">
                <p>&copy; 2024 {self.company_name}. All rights reserved.</p>
                <p>Contact us: support@myerscybersecurity.com | 1-800-CYBER-SEC</p>
            </div>
        </body>
        </html>
        """

        plain_content = f"""
        Welcome to {self.company_name}!

        Hello {user_details.get('first_name', 'there')}!

        Your 30-day free trial has started.

        Activate here: {dashboard_link}

        Plan: {user_details.get('plan', 'Professional').title()}
        """

        return self.send_email(user_details['email'], subject, html_content, plain_content)

    def send_trial_reminder(self, user_id: str, days_remaining: int) -> bool:
        """Send trial expiration reminder"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details or not user_details.get('email'):
            self.logger.warning(f"Could not retrieve user details or email for user_id {user_id} to send trial reminder.")
            return False

        discount_eligible = days_remaining <= 15
        
        if days_remaining == 7:
            subject = f"Your {self.company_name} trial expires in 7 days - Don't lose access!"
        elif days_remaining == 3:
            subject = f"Final reminder: Your {self.company_name} trial expires in 3 days"
        elif days_remaining == 1:
            subject = f"Last chance: Your {self.company_name} trial expires tomorrow!"
        else:
            subject = f"Trial reminder: {days_remaining} days remaining for {self.company_name}"
        
        # Use app_domain for all links
        pricing_link = f"{self.app_domain}/pricing"

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .urgent {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0; }}
                .content {{ padding: 20px; }}
                .button {{ background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
                .discount {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745; }}
            </style>
        </head>
        <body>
            <div class="urgent">
                <h2>⏰ Your trial expires in {days_remaining} day{'s' if days_remaining != 1 else ''}!</h2>
            </div>
            
            <div class="content">
                <p>Hi {user_details.get('first_name', 'there')},</p>
                
                <p>Your {self.company_name} trial is ending soon. Don't lose access to your cybersecurity dashboard and threat monitoring.</p>
                
                {'<div class="discount"><h3>🎉 Limited Time: 25% OFF!</h3><p>Convert now and save 25% on your first year!</p></div>' if discount_eligible else ''}
                
                <p><strong>What you\'ll lose without upgrading:</strong></p>
                <ul>
                    <li>Real-time threat detection</li>
                    <li>API key security monitoring</li>
                    <li>Advanced analytics dashboard</li>
                    <li>24/7 security alerts</li>
                </ul>
                
                <a href="{pricing_link}" class="button">Upgrade Now - From ${user_details.get('plan_price', 39)}/month</a>
                
                <p>Questions? Reply to this email or contact our support team.</p>
            </div>
        </body>
        </html>
        """
        
        plain_content = f"""
        Your trial expires in {days_remaining} day{'s' if days_remaining != 1 else ''}!

        Hi {user_details.get('first_name', 'there')},

        Your {self.company_name} trial is ending soon. Don't lose access to your cybersecurity dashboard and threat monitoring.

        {"Limited Time: 25% OFF! Convert now and save 25% on your first year!" if discount_eligible else ""}

        Upgrade Now: {pricing_link}

        Questions? Reply to this email or contact our support team.
        """

        return self.send_email(
            user_details['email'], subject, html_content, plain_content
        )
    
    def send_payment_failed_email(self, user_id: str, invoice_details: Dict) -> bool:
        """Send payment failed notification"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details or not user_details.get('email'):
            self.logger.warning(f"Could not retrieve user details or email for user_id {user_id} to send payment failed email.")
            return False
        
        subject = f"Payment Failed for {self.company_name} - Action Required for Your Account"
        
        # Use app_domain for all links
        billing_link = f"{self.app_domain}/billing"
        
        # Format amount and date defensively
        amount_display = f"${invoice_details.get('amount', 0)/100:.2f}" if isinstance(invoice_details.get('amount'), (int, float)) else "$0.00"
        date_display = invoice_details.get('date', 'today')

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .alert {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .content {{ padding: 20px; }}
                .button {{ background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <h2>⚠️ Payment Failed</h2>
                <p>We couldn't process your payment for the {user_details.get('plan', 'Professional').title()} plan.</p>
            </div>
            
            <div class="content">
                <p>Hi {user_details.get('first_name', 'there')},</p>
                
                <p>Your payment of {amount_display} failed on {date_display}.</p>
                
                <p><strong>Possible reasons:</strong></p>
                <ul>
                    <li>Insufficient funds</li>
                    <li>Expired credit card</li>
                    <li>Bank declined the transaction</li>
                    <li>Billing address mismatch</li>
                </ul>
                
                <p>Please update your payment method to continue your service without interruption.</p>
                
                <a href="{billing_link}" class="button">Update Payment Method</a>
                
                <p>Your account will be suspended in 3 days if payment is not resolved.</p>
            </div>
        </body>
        </html>
        """
        
        plain_content = f"""
        Payment Failed for {self.company_name} - Action Required!

        Hi {user_details.get('first_name', 'there')},

        Your payment of {amount_display} failed on {date_display}.

        Please update your payment method to continue your service without interruption.
        Update Payment Method: {billing_link}

        Your account will be suspended in 3 days if payment is not resolved.
        """

        return self.send_email(
            user_details['email'], subject, html_content, plain_content
        )
    
    def send_subscription_cancelled_email(self, user_id: str) -> bool:
        """Send subscription cancellation confirmation"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details or not user_details.get('email'):
            self.logger.warning(f"Could not retrieve user details or email for user_id {user_id} to send cancellation email.")
            return False
        
        subject = f"{self.company_name} Subscription Cancelled - We're Sorry to See You Go"
        
        # Use app_domain for all links
        feedback_link = f"{self.app_domain}/feedback"

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .content {{ padding: 20px; }}
                .button {{ background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="content">
                <h2>Subscription Cancelled</h2>
                
                <p>Hi {user_details.get('first_name', 'there')},</p>
                
                <p>Your {self.company_name} subscription has been cancelled. You'll continue to have access until your current billing period ends.</p>
                
                <p>We'd love to hear your feedback about why you're leaving. Your input helps us improve our service.</p>
                
                <a href="{feedback_link}" class="button">Share Feedback</a>
                
                <p>You can reactivate your account anytime. Thank you for choosing {self.company_name}.</p>
                
                <p>Best regards,<br>The {self.company_name} Team</p>
            </div>
        </body>
        </html>
        """
        
        plain_content = f"""
        {self.company_name} Subscription Cancelled

        Hi {user_details.get('first_name', 'there')},

        Your {self.company_name} subscription has been cancelled. You'll continue to have access until your current billing period ends.

        We'd love to hear your feedback about why you're leaving. Your input helps us improve our service.
        Share Feedback: {feedback_link}

        You can reactivate your account anytime. Thank you for choosing {self.company_name}.

        Best regards,
        The {self.company_name} Team
        """
        
        return self.send_email(
            user_details['email'], subject, html_content, plain_content
        )
    
    def send_security_alert_email(self, user_id: str, alert_details: Dict) -> bool:
        """Send security alert notification"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details or not user_details.get('email'):
            self.logger.warning(f"Could not retrieve user details or email for user_id {user_id} to send security alert.")
            return False
        
        subject = f"🚨 Security Alert from {self.company_name}: {alert_details.get('type', 'Suspicious Activity')} Detected"
        
        # Use app_domain for all links
        dashboard_link = f"{self.app_domain}/dashboard"

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .alert {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .content {{ padding: 20px; }}
                .button {{ background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <h2>🚨 Security Alert</h2>
                <p><strong>{alert_details.get('type', 'Suspicious Activity')}</strong> detected on your account.</p>
            </div>
            
            <div class="content">
                <p>Hi {user_details.get('first_name', 'there')},</p>
                
                <p><strong>Alert Details:</strong></p>
                <ul>
                    <li><strong>Type:</strong> {alert_details.get('type', 'Unknown')}</li>
                    <li><strong>Time:</strong> {alert_details.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</li>
                    <li><strong>Severity:</strong> {alert_details.get('severity', 'Medium').upper()}</li>
                    <li><strong>Description:</strong> {alert_details.get('description', 'Suspicious activity detected')}</li>
                </ul>
                
                <p><strong>Recommended Actions:</strong></p>
                <ul>
                    <li>Review your recent account activity</li>
                    <li>Check your API key usage logs</li>
                    <li>Update your password if necessary</li>
                    <li>Contact support if you need assistance</li>
                </ul>
                
                <a href="{dashboard_link}" class="button">Review Security Dashboard</a>
                
                <p>If you didn't trigger this alert, please contact our security team immediately.</p>
            </div>
        </body>
        </html>
        """
        
        plain_content = f"""
        Security Alert from {self.company_name}: {alert_details.get('type', 'Suspicious Activity')} Detected!

        Hi {user_details.get('first_name', 'there')},

        Alert Details:
        Type: {alert_details.get('type', 'Unknown')}
        Time: {alert_details.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
        Severity: {alert_details.get('severity', 'Medium').upper()}
        Description: {alert_details.get('description', 'Suspicious activity detected')}

        Recommended Actions:
        - Review your recent account activity
        - Check your API key usage logs
        - Update your password if necessary
        - Contact support if you need assistance

        Review Security Dashboard: {dashboard_link}

        If you didn't trigger this alert, please contact our security team immediately.
        """
        
        return self.send_email(
            user_details['email'], subject, html_content, plain_content
        )
    
    def send_bulk_trial_reminders(self) -> Dict:
        """
        Send trial reminders to users approaching expiration.
        This method now directly uses the imported Supabase client.
        """
        if not supabase:
            self.logger.error("Supabase client not initialized. Cannot send bulk trial reminders.")
            return {'error': "Supabase client not initialized."}

        try:
            # Query users from Supabase with trials ending soon
            # Assumes 'users' table has 'is_trial' (boolean), 'trial_end_date' (timestamp)
            # and 'email', 'first_name', 'id'
            
            # Fetch users who are currently on trial and whose trial ends within the next 7 days
            seven_days_from_now = datetime.now() + timedelta(days=7)
            
            response = supabase.table("users").select("id, email, first_name, trial_end_date").eq("is_trial", True).lte("trial_end_date", seven_days_from_now.isoformat()).execute()
            
            if response.data is None:
                self.logger.error(f"Supabase returned no data or an error for bulk trial reminders: {response.error}")
                return {'error': response.error.message if response.error else "Unknown Supabase error"}

            users = response.data
            
            sent_count = 0
            failed_count = 0
            
            self.logger.info(f"Found {len(users)} trial users ending within 7 days.")

            for user_data in users:
                user_id = user_data.get('id')
                user_email = user_data.get('email')
                trial_end_str = user_data.get('trial_end_date')

                if not user_id or not user_email or not trial_end_str:
                    self.logger.warning(f"Skipping user due to missing data: {user_data}")
                    failed_count += 1
                    continue

                try:
                    trial_end = datetime.fromisoformat(trial_end_str.replace('Z', '+00:00')) # Handle 'Z' for UTC
                except ValueError:
                    self.logger.error(f"Invalid trial_end_date format for user {user_id}: {trial_end_str}")
                    failed_count += 1
                    continue

                days_remaining = (trial_end - datetime.now()).days
                
                # Only send if days_remaining is exactly 7, 3, or 1
                if days_remaining in [7, 3, 1]:
                    # To avoid re-fetching user_details in send_trial_reminder,
                    # we can pass them directly if that method were modified to accept them.
                    # For now, it still calls security_core.get_user_details internally.
                    success = self.send_trial_reminder(user_id, days_remaining)
                    if success:
                        sent_count += 1
                    else:
                        failed_count += 1
                else:
                    self.logger.info(f"User {user_id} has {days_remaining} days remaining, not a target reminder day (7, 3, or 1).")
                            
            return {
                'sent': sent_count,
                'failed': failed_count,
                'total_users_considered': len(users)
            }
            
        except Exception as e:
            self.logger.error(f"Bulk reminder sending failed: {str(e)}", exc_info=True)
            return {'error': str(e)}


class EmailEventHandler:
    """Handle email automation based on system events"""
    
    def __init__(self, email_automation: EmailAutomation):
        self.email_automation = email_automation
    
    def handle_user_created(self, user_id: str):
        """Handle new user creation"""
        user_details = self.email_automation.security_core.get_user_details(user_id)
        if user_details:
            self.email_automation.send_welcome_email(user_id, user_details)
        else:
            self.email_automation.logger.error(f"User details not found for {user_id} during user creation event.")
    
    def handle_payment_failed(self, user_id: str, invoice_details: Dict):
        """Handle failed payment"""
        self.email_automation.send_payment_failed_email(user_id, invoice_details)
    
    def handle_subscription_cancelled(self, user_id: str):
        """Handle subscription cancellation"""
        self.email_automation.send_subscription_cancelled_email(user_id)
    
    def handle_security_alert(self, user_id: str, alert_details: Dict):
        """Handle security alerts"""
        # Ensure 'severity' key exists and is a string for case-insensitive comparison
        severity = alert_details.get('severity', '').lower()
        if severity in ['high', 'critical']:
            self.email_automation.send_security_alert_email(user_id, alert_details)
        else:
            self.email_automation.logger.info(f"Skipping security alert for user {user_id} due to low severity: {severity}")

# --- Example Usage (for testing purposes) ---
if __name__ == '__main__':
    # Set dummy environment variables for local testing (remove in production or use .env)
    os.environ['SENDGRID_API_KEY'] = 'SG.YOUR_SENDGRID_API_KEY' # Replace with a real test key
    os.environ['FROM_EMAIL'] = 'test@example.com'
    os.environ['DOMAIN'] = 'http://localhost:8501' # Your local Streamlit domain

    # Supabase dummy credentials - REPLACE WITH YOUR ACTUAL ONES FOR REAL TESTING
    os.environ['SUPABASE_URL'] = 'https://your-project-ref.supabase.co'
    os.environ['SUPABASE_KEY'] = 'your-anon-public-key'
    os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'your-service-role-key' # If you need admin client for testing

    # Re-import supabase client after setting env vars for __main__ block
    # In a real app, env vars would be set before the app starts and clients are initialized.
    from src.config.supabase_client import supabase, supabase_admin

    # Initialize mock security core
    mock_security_core = MockSecurityCore()
    
    # Initialize email automation system
    email_automation = EmailAutomation(mock_security_core)
    
    # Initialize event handler
    event_handler = EmailEventHandler(email_automation)

    # --- Test Cases ---

    # Mock user details for testing purposes
    test_user_id = "test_user_123"
    test_user_details = {
        "id": test_user_id,
        "email": "dustin.myers.test@example.com",
        "first_name": "Dustin",
        "plan": "Enterprise",
        "trial_token": "some_unique_trial_token_123",
        "plan_price": 99,
        "is_trial": True,
        "trial_end_date": (datetime.now() + timedelta(days=5)).isoformat() + 'Z' # Example: Trial ends in 5 days
    }

    # You'd need to mock or ensure these users exist in your Supabase 'users' table
    # for the `security_core.get_user_details` and `send_bulk_trial_reminders` to work.
    # For a real test, insert them into your test Supabase DB first.

    print("\n--- Testing Welcome Email ---")
    # Simulate a user creation event
    # If using MockSecurityCore, ensure test_user_details reflects what get_user_details would return
    # For this test, we'll pass user_details directly as if 'handle_user_created' had already fetched it.
    success_welcome = email_automation.send_welcome_email(test_user_id, test_user_details)
    print(f"Welcome email sent: {success_welcome}")

    print("\n--- Testing Trial Reminder (7 days) ---")
    # Simulate a trial reminder for a user with 7 days left
    user_7_days = {"id": "user_7d", "email": "seven.days@example.com", "first_name": "Seven", "plan_price": 49, "is_trial": True, "trial_end_date": (datetime.now() + timedelta(days=7)).isoformat() + 'Z'}
    # Mock SecurityCore to return this specific user
    # In a real app, this user would be in your DB
    mock_security_core.get_user_details = lambda u_id: user_7_days if u_id == "user_7d" else None
    success_reminder_7 = email_automation.send_trial_reminder("user_7d", 7)
    print(f"Trial reminder (7 days) sent: {success_reminder_7}")

    print("\n--- Testing Payment Failed Email ---")
    # Simulate a payment failure event
    invoice_details = {"amount": 5999, "date": "2025-06-10"}
    user_payment_fail = {"id": "user_pf", "email": "payment.fail@example.com", "first_name": "Failed", "plan": "Professional"}
    mock_security_core.get_user_details = lambda u_id: user_payment_fail if u_id == "user_pf" else None
    success_payment_fail = email_automation.send_payment_failed_email("user_pf", invoice_details)
    print(f"Payment failed email sent: {success_payment_fail}")

    print("\n--- Testing Subscription Cancelled Email ---")
    user_cancelled = {"id": "user_cancel", "email": "cancel@example.com", "first_name": "Canceled"}
    mock_security_core.get_user_details = lambda u_id: user_cancelled if u_id == "user_cancel" else None
    success_cancelled = email_automation.send_subscription_cancelled_email("user_cancel")
    print(f"Subscription cancelled email sent: {success_cancelled}")

    print("\n--- Testing Security Alert Email (High Severity) ---")
    alert_details_high = {
        "type": "Unauthorized API Access",
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "severity": "high",
        "description": "Multiple failed login attempts from unusual IP address."
    }
    user_security_alert = {"id": "user_sec", "email": "security.alert@example.com", "first_name": "Secure"}
    mock_security_core.get_user_details = lambda u_id: user_security_alert if u_id == "user_sec" else None
    success_security_alert = email_automation.send_security_alert_email("user_sec", alert_details_high)
    print(f"Security alert email sent: {success_security_alert}")

    print("\n--- Testing Bulk Trial Reminders (Requires real Supabase data or extensive mocking) ---")
    # For a real test, ensure your Supabase 'users' table has trial users setup:
    # Example:
    # INSERT INTO users (id, email, first_name, is_trial, trial_end_date) VALUES
    # ('user_bulk_1', 'bulk1@example.com', 'TestUser1', TRUE, NOW() + INTERVAL '7 days'),
    # ('user_bulk_2', 'bulk2@example.com', 'TestUser2', TRUE, NOW() + INTERVAL '3 days'),
    # ('user_bulk_3', 'bulk3@example.com', 'TestUser3', TRUE, NOW() + INTERVAL '1 day'),
    # ('user_bulk_4', 'bulk4@example.com', 'TestUser4', TRUE, NOW() + INTERVAL '10 days');
    
    # Temporarily set mock_security_core.get_user_details to return the user from bulk query
    original_get_user_details = mock_security_core.get_user_details
    def bulk_mock_get_user_details(user_id):
        # This simulates fetching the full details for send_trial_reminder if needed
        # In real code, your get_user_details would fetch from DB
        if user_id == 'user_bulk_1': return {'id': 'user_bulk_1', 'email': 'bulk1@example.com', 'first_name': 'TestUser1', 'plan_price': 39, 'is_trial': True, 'trial_end_date': (datetime.now() + timedelta(days=7)).isoformat() + 'Z'}
        if user_id == 'user_bulk_2': return {'id': 'user_bulk_2', 'email': 'bulk2@example.com', 'first_name': 'TestUser2', 'plan_price': 39, 'is_trial': True, 'trial_end_date': (datetime.now() + timedelta(days=3)).isoformat() + 'Z'}
        if user_id == 'user_bulk_3': return {'id': 'user_bulk_3', 'email': 'bulk3@example.com', 'first_name': 'TestUser3', 'plan_price': 39, 'is_trial': True, 'trial_end_date': (datetime.now() + timedelta(days=1)).isoformat() + 'Z'}
        return original_get_user_details(user_id) # Fallback to original mock
    mock_security_core.get_user_details = bulk_mock_get_user_details

    # This call now queries Supabase directly
    bulk_results = email_automation.send_bulk_trial_reminders()
    print(f"Bulk trial reminders results: {bulk_results}")
