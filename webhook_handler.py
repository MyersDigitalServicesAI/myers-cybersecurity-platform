# webhook_handler.py
"""
Stripe Webhook Handler for Production Deployment
Handles real-time payment events and updates user status
"""
import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
import stripe

# --- Internal Module Imports ---
# Corrected import path assuming SecurityCore is in security_core.py
from security_core import SecurityCore
# Assuming PaymentProcessor is in payment.py
from payment import PaymentProcessor
from email_automation import EmailAutomation, EmailEventHandler

# --- Flask App Setup ---
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Initialize Components ---
try:
    security_core = SecurityCore()
    # Use PaymentProcessor for billing operations
    payment_processor = PaymentProcessor()
    email_automation = EmailAutomation()
    email_handler = EmailEventHandler(security_core, email_automation)
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not STRIPE_WEBHOOK_SECRET:
        logger.critical("STRIPE_WEBHOOK_SECRET environment variable not set. Webhooks will not be verified.")
        raise ValueError("STRIPE_WEBHOOK_SECRET environment variable is required for webhook verification.")
except Exception as e:
    logger.critical(f"Failed to initialize core components for webhook_handler: {e}. Check environment variables and database connectivity.", exc_info=True)
    # In a real app, you might want to exit or disable webhook processing if critical components fail
    exit(1) # Exit if critical components fail to initialize

@app.route('/webhook/stripe', methods=['POST'])
def handle_stripe_webhook():
    """Handle Stripe webhook events."""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    if not sig_header:
        logger.error("Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400
    
    # Use the handle_webhook method from PaymentProcessor to verify and parse
    result = payment_processor.handle_webhook(payload, sig_header, STRIPE_WEBHOOK_SECRET)

    if 'error' in result:
        logger.error(f"Stripe webhook verification/parsing failed: {result['error']}")
        return jsonify({'error': result['error']}), 400
    
    event_data = result['data']
    event_id = event_data['event_id']
    event_type = event_data['event_type']
    customer_email = event_data.get('customer_email')
    stripe_customer_id = event_data.get('customer_id')
    subscription_id = event_data.get('subscription_id')
    status = event_data.get('status')
    current_period_end = event_data.get('current_period_end')
    price_id = event_data.get('price_id') # Get price_id from webhook data

    logger.info(f"Processing Stripe event: {event_type} (ID: {event_id}) for email: {customer_email}")

    # Implement idempotency: Check if this event has already been processed
    if security_core.is_event_already_processed(event_id, "stripe_webhook"):
        logger.info(f"Stripe webhook event {event_id} already processed. Skipping.")
        return jsonify(success=True), 200

    user_id = None
    user_details = None

    # Try to find user by Stripe Customer ID first, then by email, then by subscription ID
    if stripe_customer_id:
        user_details = security_core.get_user_by_stripe_customer_id(stripe_customer_id) # Assuming this method exists
        if user_details:
            user_id = user_details['id']
            logger.info(f"Found user {user_id} by Stripe Customer ID: {stripe_customer_id}")
    
    if not user_id and customer_email:
        user_details = security_core.get_user_by_email(customer_email)
        if user_details:
            user_id = user_details['id']
            logger.info(f"Found user {user_id} by email: {customer_email}")
            # If found by email but no customer_id, update user record with customer_id
            if stripe_customer_id and not user_details.get('stripe_customer_id'):
                security_core.update_user_subscription_status(user_id, user_details['subscription_status'], stripe_customer_id=stripe_customer_id)

    if not user_id and subscription_id:
        user_details = security_core.get_user_by_subscription_id(subscription_id)
        if user_details:
            user_id = user_details['id']
            logger.info(f"Found user {user_id} by subscription ID: {subscription_id}")
            # If found by subscription ID but no customer_id, update user record with customer_id
            if stripe_customer_id and not user_details.get('stripe_customer_id'):
                security_core.update_user_subscription_status(user_id, user_details['subscription_status'], stripe_customer_id=stripe_customer_id)


    if not user_id:
        logger.warning(f"Could not find internal user for Stripe event {event_type} (ID: {event_id}). Email: {customer_email}, Customer ID: {stripe_customer_id}, Subscription ID: {subscription_id}. Manual review needed.")
        # Log this event as processed to avoid re-processing unknown events
        security_core.mark_event_as_processed(event_id, "stripe_webhook", event_type, "User not found for webhook event.")
        return jsonify(success=True), 200 # Acknowledge webhook to Stripe

    try:
        if event_type == 'checkout.session.completed':
            # This event occurs when a customer successfully completes a Stripe Checkout Session.
            # It's typically used for new subscriptions or one-time payments.
            # Extract subscription ID and customer ID from the session object
            session = stripe.checkout.Session.retrieve(event_data['event_id'], expand=['subscription'])
            subscription_id = session.subscription.id if session.subscription else None
            stripe_customer_id = session.customer

            if subscription_id:
                # Update user's subscription status to 'active' and store Stripe IDs
                security_core.update_user_subscription_status(
                    user_id,
                    payment_status='active',
                    is_trial=False, # Assuming checkout.session.completed means trial is over or skipped
                    subscription_id=subscription_id,
                    stripe_customer_id=stripe_customer_id
                )
                logger.info(f"User {user_id} subscription activated via checkout.session.completed. Sub ID: {subscription_id}")
                email_handler.handle_payment_successful(user_id)
            else:
                logger.warning(f"Checkout session completed but no subscription ID found for user {user_id}.")

        elif event_type == 'customer.subscription.updated':
            # This event occurs when a subscription changes (e.g., plan change, status change, renewal).
            new_status = event_data['status']
            current_period_end_dt = datetime.fromtimestamp(current_period_end) if current_period_end else None
            
            internal_payment_status = 'active'
            is_trial = False
            if new_status == 'trialing':
                internal_payment_status = 'trial'
                is_trial = True
            elif new_status == 'active':
                internal_payment_status = 'active'
            elif new_status == 'past_due':
                internal_payment_status = 'past_due'
            elif new_status == 'canceled' or new_status == 'unpaid': # 'unpaid' for failed payments
                internal_payment_status = 'canceled'
            
            # Update user's subscription status in your database
            security_core.update_user_subscription_status(
                user_id,
                payment_status=internal_payment_status,
                is_trial=is_trial,
                subscription_id=subscription_id,
                trial_ends=current_period_end_dt,
                stripe_customer_id=stripe_customer_id
            )
            logger.info(f"Subscription for user {customer_email} (ID: {user_id}) updated to status: {new_status}")
            
            # Handle specific status changes for email notifications
            if internal_payment_status == 'active' and user_details.get('subscription_status') != 'active':
                email_handler.handle_payment_successful(user_id)
            elif internal_payment_status == 'canceled' and user_details.get('subscription_status') != 'canceled':
                email_handler.handle_subscription_cancelled(user_id)
            # You might want to add handling for 'past_due' or other statuses

        elif event_type == 'customer.subscription.deleted':
            # This event occurs when a subscription is explicitly deleted.
            security_core.update_user_subscription_status(user_id, 'canceled', subscription_id=subscription_id)
            logger.info(f"Subscription {subscription_id} deleted for user {customer_email} (ID: {user_id}).")
            email_handler.handle_subscription_cancelled(user_id)

        elif event_type == 'invoice.payment_succeeded':
            # This event occurs when an invoice is paid. Useful for renewals.
            # Ensure the user's status is 'active'
            security_core.update_user_subscription_status(user_id, 'active', subscription_id=subscription_id)
            logger.info(f"Invoice payment succeeded for user {customer_email} (ID: {user_id}).")
            email_handler.handle_payment_successful(user_id)

        elif event_type == 'invoice.payment_failed':
            # This event occurs when an invoice payment fails.
            invoice_details = {
                'amount': event_data.get('amount_due') / 100.0 if event_data.get('amount_due') else 'N/A', # Convert cents to dollars
                'date': datetime.fromtimestamp(event_data.get('created')).strftime('%Y-%m-%d') if event_data.get('created') else 'N/A',
                'invoice_url': event_data.get('hosted_invoice_url')
            }
            security_core.update_user_subscription_status(user_id, 'past_due', subscription_id=subscription_id)
            logger.warning(f"Invoice payment failed for user {customer_email} (ID: {user_id}).")
            email_handler.handle_payment_failed(user_id, invoice_details)

        else:
            logger.info(f"Unhandled Stripe event type: {event_type} for user {user_id}.")

        # Mark the event as processed after successful handling
        security_core.mark_event_as_processed(event_id, "stripe_webhook", event_type, f"Successfully handled {event_type}")
        
        return jsonify(success=True), 200

    except stripe.error.StripeError as e:
        logger.error(f"Stripe API error during webhook processing for event {event_id}: {e}", exc_info=True)
        return jsonify({'error': 'Stripe API error'}), 500
    except Exception as e:
        logger.error(f"Error processing Stripe webhook for event {event_id}: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify application and database status."""
    try:
        # Attempt to get and return a database connection to verify connectivity
        conn = security_core.get_connection() # Assuming security_core has a get_connection method that uses the pool
        conn.close() # Close the connection immediately after check
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {e}"
        logger.error(f"Database health check failed: {e}")

    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database_status': db_status
    }), 200

if __name__ == '__main__':
    # For local development, ensure environment variables are set
    # In production, Render will manage these.
    # Example: export STRIPE_SECRET_KEY='sk_test_...'
    # export STRIPE_WEBHOOK_SECRET='whsec_...'
    # export DATABASE_URL='postgresql://user:password@host:port/database'
    # export SENDER_EMAIL='your_email@example.com'
    # export SMTP_SERVER='smtp.sendgrid.net'
    # export SMTP_PORT='587'
    # export SMTP_USER='apikey' # For SendGrid
    # export SMTP_API_KEY='SG.YOUR_API_KEY'
    # export APP_URL='http://localhost:5000' # Or your deployed app URL

    # Initialize the database pool at application startup
    from utils.database import init_db_pool, close_db_pool
    try:
        init_db_pool()
        logger.info("Database pool initialized for webhook_handler.")
        app.run(debug=True, host='0.0.0.0', port=os.getenv('PORT', 5000))
    except Exception as e:
        logger.critical(f"Failed to start webhook handler application: {e}", exc_info=True)
    finally:
        close_db_pool()
        logger.info("Database pool closed on application shutdown.")

