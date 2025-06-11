import stripe
import os

class PaymentProcessor:
    def __init__(self):
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")  # Set in your environment

    def create_checkout_session(self, price_id, customer_email, success_url, cancel_url):
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                customer_email=customer_email,
                success_url=success_url,
                cancel_url=cancel_url,
            )
            return {"checkout_url": session.url}
        except Exception as e:
            return {"error": str(e)}

    # You can add more Stripe methods as needed
