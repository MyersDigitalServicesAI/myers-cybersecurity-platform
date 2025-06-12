# payment.py
import os
import stripe
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class PaymentProcessor:
    def __init__(self):
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
        if not stripe.api_key:
            logger.error("STRIPE_SECRET_KEY environment variable not set.")
            raise ValueError("STRIPE_SECRET_KEY environment variable is required.")

    def create_checkout_session(self, price_id, customer_email, success_url, cancel_url):
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                customer_email=customer_email,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={'customer_email': customer_email}
            )
            return {"checkout_url": session.url}
        except Exception as e:
            logger.error(f"Error creating Stripe checkout session: {e}", exc_info=True)
            return {"error": str(e)}
