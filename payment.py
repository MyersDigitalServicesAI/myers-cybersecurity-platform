# payment.py (Add or modify existing class)
import stripe
import os
import logging

logger = logging.getLogger(__name__)

class PaymentProcessor:
    def __init__(self):
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
        if not stripe.api_key:
            logger.critical("STRIPE_SECRET_KEY environment variable not set. Payment operations will fail.")
            raise ValueError("STRIPE_SECRET_KEY environment variable is required for Stripe operations.")
        logger.info("Stripe PaymentProcessor initialized.")

    def create_checkout_session(self, price_id, customer_email, success_url, cancel_url):
        # ... (your existing code for create_checkout_session) ...
        try:
            logger.info(f"Attempting to create Stripe checkout session for email: {customer_email} with price_id: {price_id}")
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                customer_email=customer_email,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'user_email': customer_email,
                    'price_id': price_id,
                }
            )
            logger.info(f"Stripe checkout session created successfully: {session.url}")
            return {"checkout_url": session.url}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error creating checkout session: {e}", exc_info=True)
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating checkout session: {e}", exc_info=True)
            return {"error": "An unexpected error occurred during checkout session creation."}

    def create_customer_portal_session(self, customer_id: str, return_url: str):
        """
        Creates a Stripe Customer Portal session URL.

        Args:
            customer_id (str): The Stripe Customer ID.
            return_url (str): The URL where the user will be redirected after exiting the portal.

        Returns:
            dict: A dictionary containing 'portal_url' on success, or 'error' on failure.
        """
        try:
            logger.info(f"Attempting to create Stripe Customer Portal session for customer: {customer_id}")
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            logger.info(f"Stripe Customer Portal session created successfully: {session.url}")
            return {"portal_url": session.url}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error creating customer portal session for {customer_id}: {e}", exc_info=True)
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating customer portal session for {customer_id}: {e}", exc_info=True)
            return {"error": "An unexpected error occurred during customer portal session creation."}

    def get_stripe_customer_id_by_email(self, email: str):
        """
        Retrieves a Stripe Customer ID by email.
        Note: Stripe recommends storing customer IDs in your DB for efficiency.
        """
        try:
            customers = stripe.Customer.list(email=email, limit=1)
            if customers.data:
                return customers.data[0].id
            return None
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error retrieving customer by email {email}: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving customer by email {email}: {e}", exc_info=True)
            return None
