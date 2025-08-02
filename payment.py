        import stripe
import os
import logging
from typing import Dict, Any, Optional

# Initialize a logger for this module
logger = logging.getLogger(__name__)

class PaymentProcessor:
    """
    Handles all interactions with the Stripe API, including creating checkouts,
    managing subscriptions, and processing webhooks.
    """
    def __init__(self):
        """
        Initializes the Stripe API client.
        CRITICAL: Ensures the STRIPE_SECRET_KEY is set in the environment.
        """
        # --- HIGH-PRIORITY FIX APPLIED ---
        # Standardized on STRIPE_SECRET_KEY as the environment variable name.
        # Ensure this matches the variable name in your Render dashboard.
        self.api_key = os.environ.get("STRIPE_SECRET_KEY")
        if not self.api_key:
            logger.critical("FATAL: STRIPE_SECRET_KEY environment variable not set. Payment operations will fail.")
            raise ValueError("STRIPE_SECRET_KEY is a required environment variable.")
        
        stripe.api_key = self.api_key
        logger.info("Stripe PaymentProcessor initialized successfully.")

    def create_checkout_session(self, price_id: str, customer_email: str, success_url: str, cancel_url: str) -> Dict[str, Any]:
        """
        Creates a Stripe Checkout session for a new subscription.
        """
        if not all([price_id, customer_email, success_url, cancel_url]):
            logger.error("Missing required arguments for create_checkout_session.")
            return {"error": "Internal server error: Missing required payment information."}
            
        try:
            logger.info(f"Creating Stripe checkout session for email: {customer_email} with price_id: {price_id}")
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                customer_email=customer_email,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'app_name': 'myers-cybersecurity', # Added for better tracking in Stripe
                    'user_email': customer_email,
                    'price_id': price_id,
                }
            )
            logger.info(f"Stripe checkout session created successfully: {session.url}")
            return {"status": "success", "checkout_url": session.url}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error creating checkout session: {e}", exc_info=True)
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating checkout session: {e}", exc_info=True)
            return {"error": "An unexpected error occurred."}

    def create_customer_portal_session(self, customer_id: str, return_url: str) -> Dict[str, Any]:
        """
        Creates a Stripe Customer Portal session for managing subscriptions.
        """
        try:
            logger.info(f"Creating Stripe Customer Portal session for customer: {customer_id}")
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            logger.info(f"Stripe Customer Portal session created successfully: {session.url}")
            return {"status": "success", "portal_url": session.url}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error creating customer portal for {customer_id}: {e}", exc_info=True)
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating customer portal for {customer_id}: {e}", exc_info=True)
            return {"error": "An unexpected error occurred."}

    def get_active_prices(self) -> Dict[str, Any]:
        """
        Retrieves a list of active, recurring Price objects from Stripe.
        """
        # --- MEDIUM-PRIORITY FIX APPLIED ---
        # Wrapped the API call in a try/except block for network resilience.
        try:
            logger.info("Retrieving active prices from Stripe.")
            prices = stripe.Price.list(active=True, expand=['data.product'])
            
            active_subscription_prices = [
                price for price in prices.data
                if price.product and price.product.active and price.recurring
            ]
            logger.info(f"Successfully retrieved {len(active_subscription_prices)} active subscription prices.")
            return {"status": "success", "prices": active_subscription_prices}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error retrieving active prices: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error retrieving active prices: {e}", exc_info=True)
            return {"status": "error", "error": "An unexpected error occurred."}

    def handle_webhook(self, payload: str, sig_header: str, webhook_secret: str) -> Dict[str, Any]:
        """
        Handles and verifies Stripe webhook events.
        """
        if not all([payload, sig_header, webhook_secret]):
            logger.error("Webhook handler called with missing payload, signature, or secret.")
            return {"status": "error", "error": "Missing webhook data."}

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except ValueError as e:
            logger.error(f"Invalid payload for Stripe webhook: {e}", exc_info=True)
            return {"status": "error", "error": "Invalid payload"}
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid signature for Stripe webhook: {e}", exc_info=True)
            return {"status": "error", "error": "Invalid signature"}
        except Exception as e:
            logger.error(f"Unexpected error constructing webhook event: {e}", exc_info=True)
            return {"status": "error", "error": "An unexpected error occurred."}

        # --- MEDIUM-PRIORITY FIX APPLIED ---
        # Using a structured if/elif block to handle specific events cleanly.
        event_type = event['type']
        data_object = event['data']['object']
        logger.info(f"Processing verified Stripe webhook event: {event_type} (ID: {event['id']})")

        processed_data = {
            'event_id': event['id'],
            'event_type': event_type,
        }

        if event_type == 'checkout.session.completed':
            processed_data['customer_id'] = data_object.get('customer')
            processed_data['subscription_id'] = data_object.get('subscription')
            if data_object.get('customer_details'):
                processed_data['customer_email'] = data_object['customer_details'].get('email')

        elif event_type == 'invoice.payment_succeeded':
            processed_data['customer_id'] = data_object.get('customer')
            processed_data['customer_email'] = data_object.get('customer_email')
            processed_data['subscription_id'] = data_object.get('subscription')
            processed_data['invoice_pdf'] = data_object.get('hosted_invoice_url')
            
        elif event_type in ['customer.subscription.updated', 'customer.subscription.deleted']:
            processed_data['customer_id'] = data_object.get('customer')
            processed_data['subscription_id'] = data_object.get('id')
            processed_data['status'] = data_object.get('status')
            processed_data['current_period_end'] = data_object.get('current_period_end')
            if data_object.get('items', {}).get('data'):
                processed_data['price_id'] = data_object['items']['data'][0].get('price', {}).get('id')

        else:
            logger.warning(f"Received unhandled webhook event type: {event_type}")
            return {"status": "ignored", "reason": f"Unhandled event type: {event_type}"}

        return {"status": "success", "data": processed_data}

