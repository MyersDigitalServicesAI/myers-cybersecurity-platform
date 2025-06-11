"""
Stripe Webhook Handler for Production Deployment
Handles real-time payment events and updates user status
"""
import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from security_core import SecurityCore
from billing_manager import BillingManager
from email_automation import EmailAutomation, EmailEventHandler
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
security_core = SecurityCore()
billing_manager = BillingManager()
email_automation = EmailAutomation(security_core)
email_handler = EmailEventHandler(email_automation)

@app.route('/webhook/stripe', methods=['POST'])
def handle_stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    if not sig_header:
        logger.error("Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400
    
    # Process webhook with billing manager
    result = billing_manager.handle_webhook(payload, sig_header)
    
    if 'error' in result:
        logger.error(f"Webhook processing failed: {result['error']}")
        return jsonify({'error': result['error']}), 400
    
    # Handle specific event types
    event_type = result.get('event_type')
    
    if event_type == 'payment_completed':
        handle_payment_completed(result)
    elif event_type == 'payment_failed':
        handle_payment_failed(result)
    elif event_type == 'subscription_cancelled':
        handle_subscription_cancelled(result)
    
    return jsonify({'status': 'success'}), 200

def handle_payment_completed(event_data):
    """Handle successful payment completion"""
    try:
        customer_email = event_data.get('customer_email')
        subscription_id = event_data.get('subscription_id')
        
        if not customer_email:
            return
        
        # Find user by email
        conn = security_core.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (customer_email,))
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            
            # Update user to paid status
            cursor.execute("""
                UPDATE users 
                SET is_trial = false, payment_status = 'active', subscription_id = %s
                WHERE id = %s
            """, (subscription_id, user_id))
            
            conn.commit()
            
            # Log successful payment
            if hasattr(security_core, "log_security_event"):
                security_core.log_security_event(
                    user_id, 'payment_completed', 'info',
                    f'Payment completed successfully for subscription {subscription_id}'
                )
            
            logger.info(f"Payment completed for user {customer_email}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"Error handling payment completion: {str(e)}")

def handle_payment_failed(event_data):
    """Handle failed payment"""
    try:
        subscription_id = event_data.get('subscription_id')
        
        if not subscription_id:
            return
        
        # Find user by subscription ID
        conn = security_core.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM users WHERE subscription_id = %s", (subscription_id,))
        result = cursor.fetchone()
        
        if result:
            user_id, email = result
            
            # Update payment status
            cursor.execute("""
                UPDATE users 
                SET payment_status = 'failed'
                WHERE id = %s
            """, (user_id,))
            
            conn.commit()
            
            # Send payment failed email
            invoice_details = {
                'amount': 0,  # Would be populated from actual webhook data
                'date': datetime.now().strftime('%Y-%m-%d')
            }
            email_handler.handle_payment_failed(user_id, invoice_details)
            
            # Log payment failure
            if hasattr(security_core, "log_security_event"):
                security_core.log_security_event(
                    user_id, 'payment_failed', 'warning',
                    f'Payment failed for subscription {subscription_id}'
                )
            
            logger.warning(f"Payment failed for user {email}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"Error handling payment failure: {str(e)}")

def handle_subscription_cancelled(event_data):
    """Handle subscription cancellation"""
    try:
        subscription_id = event_data.get('subscription_id')
        
        if not subscription_id:
            return
        
        # Find user by subscription ID
        conn = security_core.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE subscription_id = %s", (subscription_id,))
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            
            # Update subscription status
            cursor.execute("""
                UPDATE users 
                SET payment_status = 'cancelled'
                WHERE id = %s
            """, (user_id,))
            
            conn.commit()
            
            # Send cancellation email
            email_handler.handle_subscription_cancelled(user_id)
            
            # Log cancellation
            if hasattr(security_core, "log_security_event"):
                security_core.log_security_event(
                    user_id, 'subscription_cancelled', 'info',
                    f'Subscription cancelled: {subscription_id}'
                )
            
            logger.info(f"Subscription cancelled: {subscription_id}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"Error handling subscription cancellation: {str(e)}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
