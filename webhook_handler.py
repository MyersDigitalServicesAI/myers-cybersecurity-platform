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

# --- Internal Module Imports ---
from security_core import SecurityCore  # Updated import
from billing import BillingManager  # New import
from email_automation import EmailAutomation, EmailEventHandler

# --- Flask App Setup ---
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Initialize Components ---
try:
    security_core = SecurityCore()
    billing_manager = BillingManager()
    email_automation = EmailAutomation()
    email_handler = EmailEventHandler(security_core, email_automation)
except Exception as e:
    logger.critical(f"Failed to initialize core components for webhook_handler: {e}. Check environment variables and database connectivity.", exc_info=True)
    exit(1)


# --- Stripe Webhook Endpoint ---
@app.route('/webhook/stripe', methods=['POST'])
def handle_stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    if not sig_header:
        logger.error("Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400

    result = billing_manager.handle_webhook(payload, sig_header)

    if 'error' in result:
        logger.error(f"Webhook processing failed due to verification or payload issue: {result['error']}")
        return jsonify({'error': result['error']}), 400

    event_id = result.get('event_id')
    event_type = result.get('event_type')

    if security_core.is_event_already_processed(event_id):
        logger.info(f"Skipping already processed event: {event_id} ({event_type})")
        return jsonify({'status': 'already processed'}), 200

    try:
        if event_type == 'invoice.payment_succeeded':
            handle_payment_completed(result)
        elif event_type == 'invoice.payment_failed':
            handle_payment_failed(result)
        elif event_type == 'customer.subscription.deleted':
            handle_subscription_cancelled(result)
        elif event_type == 'customer.subscription.updated':
            handle_subscription_updated(result)
        elif event_type == 'checkout.session.completed':
            handle_checkout_session_completed(result)
        else:
            logger.info(f"Unhandled Stripe event type: {event_type} (ID: {event_id})")

        security_core.mark_event_as_processed(event_id, event_type)

    except Exception as e:
        logger.error(f"Error processing Stripe event {event_type} (ID: {event_id}): {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

    return jsonify({'status': 'success'}), 200


def handle_checkout_session_completed(event_data):
    customer_email = event_data.get('customer_email')
    subscription_id = event_data.get('subscription_id')

    if not customer_email or not subscription_id:
        logger.warning(f"Checkout session completed event missing crucial data: {event_data}")
        return

    user_id = security_core.get_user_id_by_email(customer_email)

    if user_id:
        security_core.update_user_subscription_status(
            user_id,
            payment_status='active',
            is_trial=False,
            subscription_id=subscription_id,
            trial_ends=None
        )
        security_core.log_security_event(
            user_id, 'checkout_completed', 'info',
            f'Checkout session completed for subscription {subscription_id}. User linked.'
        )
        logger.info(f"Checkout session completed for user {customer_email} (ID: {user_id}) and linked to subscription {subscription_id}.")
    else:
        logger.warning(f"Checkout session completed for unknown user email: {customer_email}. Manual review needed.")


def handle_payment_completed(event_data):
    subscription_id = event_data.get('subscription_id')
    customer_email = event_data.get('customer_email')
    current_period_end = event_data.get('current_period_end')

    if not customer_email and not subscription_id:
        logger.warning(f"Payment completed event missing customer_email or subscription_id: {event_data}")
        return

    user_id = security_core.get_user_id_by_email(customer_email)
    if not user_id and subscription_id:
        user_id = security_core.get_user_id_by_subscription_id(subscription_id)

    if user_id:
        security_core.update_user_subscription_status(
            user_id,
            payment_status='active',
            is_trial=False,
            subscription_id=subscription_id,
            trial_ends=datetime.fromtimestamp(current_period_end) if current_period_end else None
        )

        security_core.log_security_event(
            user_id, 'payment_completed', 'info',
            f'Payment completed successfully for subscription {subscription_id}'
        )
        logger.info(f"Payment completed for user {customer_email} (ID: {user_id}) for subscription {subscription_id}")

        email_handler.handle_payment_successful(user_id)
    else:
        logger.warning(f"Payment completed for unknown user (email: {customer_email}, sub_id: {subscription_id}). Manual review needed.")


def handle_payment_failed(event_data):
    subscription_id = event_data.get('subscription_id')
    customer_email = event_data.get('customer_email')

    if not subscription_id and not customer_email:
        logger.warning(f"Payment failed event missing subscription_id or customer_email: {event_data}")
        return

    user_id = security_core.get_user_id_by_subscription_id(subscription_id)
    if not user_id and customer_email:
        user_id = security_core.get_user_id_by_email(customer_email)

    if user_id:
        security_core.update_user_subscription_status(user_id, payment_status='failed')

        invoice_details = {
            'amount': event_data.get('amount_due', 0) / 100,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'invoice_url': event_data.get('invoice_pdf')
        }
        email_handler.handle_payment_failed(user_id, invoice_details)

        security_core.log_security_event(
            user_id, 'payment_failed', 'warning',
            f'Payment failed for subscription {subscription_id}'
        )
        logger.warning(f"Payment failed for user {customer_email} (ID: {user_id}, Subscription: {subscription_id})")
    else:
        logger.warning(f"Payment failed for unknown subscription ID: {subscription_id} and email: {customer_email}. Manual review needed.")


def handle_subscription_cancelled(event_data):
    subscription_id = event_data.get('subscription_id')
    customer_email = event_data.get('customer_email')

    if not subscription_id and not customer_email:
        logger.warning(f"Subscription cancelled event missing subscription_id or customer_email: {event_data}")
        return

    user_id = security_core.get_user_id_by_subscription_id(subscription_id)
    if not user_id and customer_email:
        user_id = security_core.get_user_id_by_email(customer_email)

    if user_id:
        security_core.update_user_subscription_status(user_id, payment_status='cancelled', subscription_id=None)

        email_handler.handle_subscription_cancelled(user_id)

        security_core.log_security_event(
            user_id, 'subscription_cancelled', 'info',
            f'Subscription cancelled: {subscription_id}'
        )
        logger.info(f"Subscription cancelled for user {customer_email} (ID: {user_id}, Subscription: {subscription_id})")
    else:
        logger.warning(f"Subscription cancelled for unknown subscription ID: {subscription_id} and email: {customer_email}. Manual review needed.")


def handle_subscription_updated(event_data):
    subscription_id = event_data.get('subscription_id')
    customer_email = event_data.get('customer_email')
    new_status = event_data.get('status')
    current_period_end = event_data.get('current_period_end')

    if not subscription_id or not new_status:
        logger.warning(f"Subscription updated event missing required data: {event_data}")
        return

    user_id = security_core.get_user_id_by_subscription_id(subscription_id)
    if not user_id and customer_email:
        user_id = security_core.get_user_id_by_email(customer_email)

    if user_id:
        internal_payment_status = new_status
        is_trial = False
        if new_status == 'trialing':
            internal_payment_status = 'trial'
            is_trial = True
        elif new_status == 'active':
            internal_payment_status = 'active'
            is_trial = False
        elif new_status == 'past_due':
            internal_payment_status = 'past_due'
        elif new_status == 'canceled':
            internal_payment_status = 'cancelled'

        security_core.update_user_subscription_status(
            user_id,
            payment_status=internal_payment_status,
            is_trial=is_trial,
            subscription_id=subscription_id,
            trial_ends=datetime.fromtimestamp(current_period_end) if current_period_end else None
        )
        logger.info(f"Subscription for user {customer_email} (ID: {user_id}) updated to status: {new_status}")

        security_core.log_security_event(
            user_id, 'subscription_updated', 'info',
            f'Subscription {subscription_id} updated to status: {new_status}'
        )
    else:
        logger.warning(f"Subscription updated event for unknown subscription ID: {subscription_id} and email: {customer_email}. Manual review needed.")


@app.route('/health', methods=['GET'])
def health_check():
    try:
        conn = security_core.get_connection()
        conn.close()
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
    app.run(host='0.0.0.0', port=5001, debug=False)
