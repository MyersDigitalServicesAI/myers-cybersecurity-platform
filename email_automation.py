"""
Email Automation System with SendGrid Integration
Handles user lifecycle emails, trial notifications, and payment alerts
"""
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Personalization, To, From, Subject, HtmlContent, PlainTextContent


class EmailAutomation:
    def __init__(self,to_email:str security_core):
        self.security_core = security_core
        self.sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
        self.from_email = os.getenv('FROM_EMAIL', 'noreply@myerscybersecurity.com')
        self.company_name = "Myers Cybersecurity"
        
        if self.sendgrid_api_key:
            self.sg = SendGridAPIClient(api_key=self.sendgrid_api_key)
        else:
            self.sg = None
            
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def send_welcome_email(self, to_email: str, subject: str, html_content: str, plain_content: str = "") -> bool:
    """Send welcome email to new users"""
    subject = f"Welcome to {self.company_name} - Your Cybersecurity Journey Begins"

    trial_token = user_details.get("trial_token")
    dashboard_link = f"https://your-domain.com/activate?token={trial_token}"

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
        if not user_details:
            return False
        
        discount_eligible = days_remaining <= 15
        
        if days_remaining == 7:
            subject = "Your trial expires in 7 days - Don't lose access!"
        elif days_remaining == 3:
            subject = "Final reminder: Trial expires in 3 days"
        elif days_remaining == 1:
            subject = "Last chance: Trial expires tomorrow"
        else:
            subject = f"Trial reminder: {days_remaining} days remaining"
        
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
                
                <p><strong>What you'll lose without upgrading:</strong></p>
                <ul>
                    <li>Real-time threat detection</li>
                    <li>API key security monitoring</li>
                    <li>Advanced analytics dashboard</li>
                    <li>24/7 security alerts</li>
                </ul>
                
                <a href="https://your-domain.com/pricing" class="button">Upgrade Now - From ${user_details.get('plan_price', 39)}/month</a>
                
                <p>Questions? Reply to this email or contact our support team.</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(
            user_details['email'], subject, html_content
        )
    
    def send_payment_failed_email(self, user_id: str, invoice_details: Dict) -> bool:
        """Send payment failed notification"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details:
            return False
        
        subject = "Payment Failed - Action Required for Your Account"
        
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
                
                <p>Your payment of ${invoice_details.get('amount', 0)/100:.2f} failed on {invoice_details.get('date', 'today')}.</p>
                
                <p><strong>Possible reasons:</strong></p>
                <ul>
                    <li>Insufficient funds</li>
                    <li>Expired credit card</li>
                    <li>Bank declined the transaction</li>
                    <li>Billing address mismatch</li>
                </ul>
                
                <p>Please update your payment method to continue your service without interruption.</p>
                
                <a href="https://your-domain.com/billing" class="button">Update Payment Method</a>
                
                <p>Your account will be suspended in 3 days if payment is not resolved.</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(
            user_details['email'], subject, html_content
        )
    
    def send_subscription_cancelled_email(self, user_id: str) -> bool:
        """Send subscription cancellation confirmation"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details:
            return False
        
        subject = "Subscription Cancelled - We're Sorry to See You Go"
        
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
                
                <a href="https://your-domain.com/feedback" class="button">Share Feedback</a>
                
                <p>You can reactivate your account anytime. Thank you for choosing {self.company_name}.</p>
                
                <p>Best regards,<br>The {self.company_name} Team</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(
            user_details['email'], subject, html_content
        )
    
    def send_security_alert_email(self, user_id: str, alert_details: Dict) -> bool:
        """Send security alert notification"""
        user_details = self.security_core.get_user_details(user_id)
        if not user_details:
            return False
        
        subject = f"🚨 Security Alert: {alert_details.get('type', 'Suspicious Activity')} Detected"
        
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
                
                <a href="https://your-domain.com/dashboard" class="button">Review Security Dashboard</a>
                
                <p>If you didn't trigger this alert, please contact our security team immediately.</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(
            user_details['email'], subject, html_content
        )
    
    def send_bulk_trial_reminders(self) -> Dict:
        """Send trial reminders to users approaching expiration"""
        try:
            conn = self.security_core.get_connection()
            cursor = conn.cursor()
            
            # Find users with trials expiring in 7, 3, or 1 day
            cursor.execute("""
                SELECT id, email, first_name, trial_end_date 
                FROM users 
                WHERE is_trial = true 
                AND trial_end_date BETWEEN NOW() AND NOW() + INTERVAL '7 days'
            """)
            
            users = cursor.fetchall()
            conn.close()
            
            sent_count = 0
            failed_count = 0
            
            for user in users:
                user_id, email, first_name, trial_end = user
                days_remaining = (trial_end - datetime.now()).days
                
                if days_remaining in [7, 3, 1]:
                    success = self.send_trial_reminder(user_id, days_remaining)
                    if success:
                        sent_count += 1
                    else:
                        failed_count += 1
            
            return {
                'sent': sent_count,
                'failed': failed_count,
                'total_users': len(users)
            }
            
        except Exception as e:
            self.logger.error(f"Bulk reminder sending failed: {str(e)}")
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
    
    def handle_payment_failed(self, user_id: str, invoice_details: Dict):
        """Handle failed payment"""
        self.email_automation.send_payment_failed_email(user_id, invoice_details)
    
    def handle_subscription_cancelled(self, user_id: str):
        """Handle subscription cancellation"""
        self.email_automation.send_subscription_cancelled_email(user_id)
    
    def handle_security_alert(self, user_id: str, alert_details: Dict):
        """Handle security alerts"""
        if alert_details.get('severity') in ['high', 'critical']:
            self.email_automation.send_security_alert_email(user_id, alert_details)
