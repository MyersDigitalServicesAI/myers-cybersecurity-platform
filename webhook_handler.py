import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify
import stripe
from psycopg2 import errors

# --- Internal Module Imports ---
# These must be in the same directory or in a properly configured Python path.
from security_core import SecurityCore
from payment import PaymentProcessor
from email_automation import EmailAutomation, EmailEventHandler
from utils.database import init_db_pool, close_db_pool, get_db_connection, return_db_connection

# --- Flask App Setup ---
app = Flask(__name__)

# --- Logging Configuration ---
# Configure logging once at the start of the application.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Global Component Initialization ---
# This block runs once when the application starts.
try:
    # Initialize the database pool first, as other components depend on it.
    init_db_pool()
    
    security_core = SecurityCore()
    payment_processor = PaymentProcessor()
    email_automation = EmailAutomation()
    email_handler = EmailEventHandler(security_core, email_automation)
    
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not STRIPE_WEBHOOK_SECRET:
        logger.critical("FATAL: STRIPE_WEBHOOK_SECRET environment variable not set. Webhooks cannot be verified.")
        raise ValueError("STRIPE_WEBHOOK_SECRET is required.")
        
    logger.info("All core components initialized successfully.")
except Exception as e:
    logger.critical(f"FATAL: Application failed to initialize: {e}", exc_info=True)
    # In a containerized environment, it's better to let the app run and fail health checks
    # than to exit immediately, which can cause a crash loop.
    # exit(1) # Avoid using exit() in web applications.

def handle_event_idempotency(event_id: str, event_source: str) -> bool:
    """
    Atomically checks for and records an event ID to prevent reprocessing.
    Returns True if the event is new, False if it's a duplicate.
    This fixes the "Non-Atomic Idempotency Check" finding.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # The UNIQUE index on (event_id, event_source) makes this atomic.
            cursor.execute(
                "INSERT INTO security_events (event_id, event_source, event_type, severity, description) VALUES (%s, %s, %s, %s, %s)",
                (event_id, event_source, 'webhook_received', 'info', f"Stripe event {event_id} received.")
            )
            conn.commit()
        return True # Insert was successful, so it's a new event.
    except errors.UniqueViolation:
        # This is the expected error for a duplicate event.
        logger.warning(f"Duplicate event received: ID={event_id}, Source={event_source}. Skipping.")
        conn.rollback() # Rollback the failed transaction
        return False
    except Exception as e:
        logger.error(f"Error during idempotency check for event {event_id}: {e}", exc_info=True)
        if conn:
            conn.rollback()
        # Err on the side of caution: if the check fails, don't process the event.
        return False
    finally:
        if conn:
            return_db_connection(conn)

@app.route('/webhook/stripe', methods=['POST'])
def handle_stripe_webhook():
    """Handle Stripe webhook events."""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    if not sig_header:
        logger.error("Webhook request missing Stripe-Signature header.")
        return jsonify({'error': 'Missing signature'}), 400
    
    # Use the hardened handle_webhook method from PaymentProcessor
    result = payment_processor.handle_webhook(payload, sig_header, STRIPE_WEBHOOK_SECRET)

    if result.get("status") != "success":
        error_msg = result.get('error', 'Webhook verification failed.')
        logger.error(f"Stripe webhook processing failed: {error_msg}")
        return jsonify({'error': error_msg}), 400
    
    event_data = result['data']
    event_id = event_data['event_id']
    event_type = event_data['event_type']

    # --- ATOMIC IDEMPOTENCY CHECK ---
    if not handle_event_idempotency(event_id, "stripe"):
        return jsonify(status="duplicate"), 200

    # --- EFFICIENT USER LOOKUP ---
    stripe_customer_id = event_data.get('customer_id')
    user = security_core.get_user_by_stripe_customer_id(stripe_customer_id) if stripe_customer_id else None

    if not user and event_data.get('customer_email'):
        user = security_core.get_user_by_email(event_data['customer_email'])
        # If we found the user by email, update their record with the Stripe ID for future lookups.
        if user and stripe_customer_id:
            security_core.update_user(user['id'], {'stripe_customer_id': stripe_customer_id})
            logger.info(f"Linked Stripe Customer ID {stripe_customer_id} to user {user['id']}.")

    if not user:
        logger.warning(f"Could not find internal user for Stripe event {event_type} (ID: {event_id}). Manual review may be needed.")
        return jsonify(status="user not found"), 200

    user_id = user['id']
    logger.info(f"Processing event {event_type} for user {user_id}.")

    # --- REFACTORED WEBHOOK LOGIC ---
    # This logic now uses the consolidated security_core.update_user method.
    try:
        if event_type == 'checkout.session.completed':
            update_payload = {
                'stripe_subscription_id': event_data.get('subscription_id'),
                'subscription_status': 'active'
            }
            security_core.update_user(user_id, {k: v for k, v in update_payload.items() if v})
            email_handler.handle_payment_successful(user_id)

        elif event_type in ['customer.subscription.updated', 'invoice.payment_succeeded']:
            stripe_status = event_data.get('status') # 'active', 'trialing', 'past_due', etc.
            
            # Map Stripe status to our internal status
            status_map = {
                'active': 'active',
                'trialing': 'trialing',
                'past_due': 'past_due',
                'unpaid': 'past_due',
                'canceled': 'canceled'
            }
            internal_status = status_map.get(stripe_status, user['subscription_status'])

            update_payload = {
                'subscription_status': internal_status,
                'trial_end_date': datetime.fromtimestamp(event_data['current_period_end']) if event_data.get('current_period_end') else user.get('trial_end_date')
            }
            security_core.update_user(user_id, update_payload)

            # Send emails only on meaningful status changes
            if internal_status == 'active' and user['subscription_status'] != 'active':
                email_handler.handle_payment_successful(user_id)

        elif event_type == 'customer.subscription.deleted':
            security_core.update_user(user_id, {'subscription_status': 'canceled'})
            email_handler.handle_subscription_cancelled(user_id)

        elif event_type == 'invoice.payment_failed':
            security_core.update_user(user_id, {'subscription_status': 'past_due'})
            invoice_details = {'amount': event_data.get('amount_due'), 'invoice_url': event_data.get('hosted_invoice_url')}
            email_handler.handle_payment_failed(user_id, invoice_details)

        else:
            logger.info(f"Webhook event type {event_type} received but not handled.")

        return jsonify(status="success"), 200

    except Exception as e:
        logger.error(f"Error processing Stripe webhook for event {event_id}: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify application and database status."""
    # --- FIX APPLIED (Health Check) ---
    # The health check now correctly uses the database utility functions.
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1;")
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"
        logger.error(f"Database health check failed: {e}")
        return jsonify(status='unhealthy', database_status=db_status), 503
    finally:
        if conn:
            return_db_connection(conn)
            
    return jsonify(status='ok', database_status=db_status), 200

# This block allows running the app directly for local development.
# In production, a WSGI server like Gunicorn will import the 'app' object.
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001)) # Use a different port from the main app
    app.run(debug=True, host='0.0.0.0', port=port)

# Define a function to be called on application shutdown
@app.teardown_appcontext
def shutdown_session(exception=None):
    # This is a good place for cleanup, but closing the pool should be done
    # at the process exit, not per-request. The gunicorn --preload flag
    # is a good place to initialize the pool.
    pass
