"""
Production Billing and Payment Processing Module
Real Stripe integration for live payment processing
"""
import os
import secrets
import re
import stripe
import logging
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, List

class BillingManager:
    def __init__(self):
        self.stripe_publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
        self.stripe_secret_key = os.getenv('STRIPE_SECRET_KEY')
        self.webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        # Configure Stripe with secret key if available
        if self.stripe_secret_key:
            stripe.api_key = self.stripe_secret_key
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def set_stripe_credentials(self, publishable_key: str, secret_key: str, webhook_secret: str = None):
        """Set Stripe API credentials with validation"""
        if not self.validate_stripe_key(publishable_key, 'publishable'):
            raise ValueError("Invalid Stripe publishable key format")
        if not self.validate_stripe_key(secret_key, 'secret'):
            raise ValueError("Invalid Stripe secret key format")
        
        self.stripe_publishable_key = publishable_key
        self.stripe_secret_key = secret_key
        self.webhook_secret = webhook_secret
        
        # Configure Stripe API
        stripe.api_key = secret_key
    
    def validate_stripe_key(self, key: str, key_type: str) -> bool:
        """Validate Stripe API key format"""
        if key_type == 'publishable':
            return bool(re.match(r'^pk_(test_|live_)[a-zA-Z0-9]{24,}$', key))
        elif key_type == 'secret':
            return bool(re.match(r'^sk_(test_|live_)[a-zA-Z0-9]{24,}$', key))
        return False
    
    def get_plan_pricing(self) -> Dict[str, Dict]:
        """Get pricing information for all plans with discounts"""
        base_prices = {
            'essentials': {
                'monthly': 49,
                'yearly': 490,  # 10 months after auto-renewal discount
                'features': ['2 API keys', 'Basic monitoring', '30-day logs', 'Email support']
            },
            'basic': {
                'monthly': 89,
                'yearly': 890,
                'features': ['5 API keys', 'Advanced monitoring', '60-day logs', 'Priority support']
            },
            'professional': {
                'monthly': 299,
                'yearly': 2990,
                'features': ['50 API keys', 'Real-time detection', '1-year logs', '24/7 phone support']
            },
            'business': {
                'monthly': 489,
                'yearly': 4890,
                'features': ['100 API keys', 'Advanced analytics', 'Priority support', 'Custom integrations']
            },
            'enterprise': {
                'monthly': 999,
                'yearly': 9990,
                'features': ['Unlimited API keys', 'Custom integrations', 'Unlimited logs', 'Dedicated support']
            }
        }
        
        # Apply auto-renewal discount ($10 off monthly)
        for plan in base_prices:
            base_prices[plan]['monthly'] -= 10
            base_prices[plan]['yearly'] = base_prices[plan]['monthly'] * 10  # 2 months free
            base_prices[plan]['annual_savings'] = (base_prices[plan]['monthly'] + 10) * 12 - base_prices[plan]['yearly']
        
        return base_prices
    
    def validate_plan_id(self, plan_id: str) -> bool:
        """Validate that plan ID is legitimate"""
        valid_plans = ['essentials', 'basic', 'professional', 'business', 'enterprise']
        return plan_id in valid_plans
    
    def calculate_trial_discount(self, base_price: int, trial_start_date: datetime) -> Tuple[int, str]:
        """Calculate 25% trial conversion discount if within 15 days"""
        days_since_trial = (datetime.now() - trial_start_date).days
        
        if days_since_trial <= 15:
            discount_amount = int(base_price * 0.25)
            return discount_amount, f"25% trial conversion discount (save ${discount_amount})"
        
        return 0, ""
    
    def create_checkout_session(self, plan_id: str, billing_period: str, user_email: str, 
                              trial_start_date: datetime = None) -> Dict:
        """Create real Stripe checkout session"""
        if not self.stripe_secret_key:
            return {'error': 'Stripe API keys not configured. Please add STRIPE_SECRET_KEY environment variable.'}
        
        if not self.validate_plan_id(plan_id):
            return {'error': 'Invalid plan ID'}
        
        if billing_period not in ['monthly', 'yearly']:
            return {'error': 'Invalid billing period'}
        
        try:
            pricing = self.get_plan_pricing()
            plan_price = pricing[plan_id][billing_period]
            
            # Apply trial discount if applicable
            trial_discount = 0
            if trial_start_date:
                trial_discount, _ = self.calculate_trial_discount(plan_price, trial_start_date)
            
            final_price = max(plan_price - trial_discount, 0)
            
            # Create Stripe price object
            price_data = {
                'currency': 'usd',
                'unit_amount': final_price * 100,  # Convert to cents
                'product_data': {
                    'name': f'Myers Cybersecurity - {plan_id.title()} Plan',
                    'description': f'{plan_id.title()} plan with {billing_period} billing'
                }
            }
            
            if billing_period == 'yearly':
                price_data['recurring'] = {'interval': 'year'}
            else:
                price_data['recurring'] = {'interval': 'month'}
            
            # Create checkout session
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': price_data,
                    'quantity': 1,
                }],
                mode='subscription',
                customer_email=user_email,
                success_url=f'{os.getenv("DOMAIN", "https://your-domain.com")}/success?session_id={{CHECKOUT_SESSION_ID}}',
                cancel_url=f'{os.getenv("DOMAIN", "https://your-domain.com")}/pricing',
                metadata={
                    'plan_id': plan_id,
                    'billing_period': billing_period,
                    'trial_discount': str(trial_discount),
                    'original_price': str(plan_price)
                },
                subscription_data={
                    'metadata': {
                        'plan_id': plan_id,
                        'billing_period': billing_period
                    }
                }
            )
            
            self.logger.info(f"Created checkout session {session.id} for {user_email}")
            
            return {
                'session_id': session.id,
                'checkout_url': session.url,
                'plan_id': plan_id,
                'billing_period': billing_period,
                'base_price': plan_price,
                'trial_discount': trial_discount,
                'final_price': final_price,
                'currency': 'usd'
            }
            
        except stripe.error.StripeError as e:
            self.logger.error(f"Stripe error creating checkout session: {str(e)}")
            return {'error': f'Payment processing error: {str(e)}'}
        except Exception as e:
            self.logger.error(f"Error creating checkout session: {str(e)}")
            return {'error': 'Failed to create checkout session'}
    
    def verify_payment(self, session_id: str) -> Dict:
        """Verify real Stripe payment completion"""
        if not self.stripe_secret_key:
            return {'status': 'error', 'error': 'Stripe not configured'}
        
        if not session_id or not session_id.startswith('cs_'):
            return {'status': 'invalid', 'error': 'Invalid session ID'}
        
        try:
            # Retrieve the checkout session from Stripe
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                # Get the subscription details
                subscription = None
                if session.subscription:
                    subscription = stripe.Subscription.retrieve(session.subscription)
                
                return {
                    'status': 'completed',
                    'payment_status': session.payment_status,
                    'customer_email': session.customer_email,
                    'customer_id': session.customer,
                    'amount_total': session.amount_total,
                    'subscription_id': session.subscription,
                    'subscription_status': subscription.status if subscription else None,
                    'current_period_end': subscription.current_period_end if subscription else None,
                    'plan_id': session.metadata.get('plan_id'),
                    'billing_period': session.metadata.get('billing_period')
                }
            else:
                return {
                    'status': 'pending',
                    'payment_status': session.payment_status,
                    'customer_email': session.customer_email
                }
                
        except stripe.error.StripeError as e:
            self.logger.error(f"Stripe error verifying payment: {str(e)}")
            return {'status': 'error', 'error': f'Payment verification failed: {str(e)}'}
        except Exception as e:
            self.logger.error(f"Error verifying payment: {str(e)}")
            return {'status': 'error', 'error': 'Payment verification failed'}
    
    def handle_webhook(self, payload: str, signature: str) -> Dict:
        """Handle Stripe webhook events with signature verification"""
        if not self.webhook_secret:
            return {'error': 'Webhook secret not configured. Add STRIPE_WEBHOOK_SECRET environment variable.'}
        
        try:
            # Verify webhook signature
            event = stripe.Webhook.construct_event(payload, signature, self.webhook_secret)
            
            # Handle different event types
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                self.logger.info(f"Payment completed for session {session['id']}")
                return {
                    'status': 'processed',
                    'event_type': 'payment_completed',
                    'session_id': session['id'],
                    'customer_email': session.get('customer_email'),
                    'subscription_id': session.get('subscription')
                }
            
            elif event['type'] == 'invoice.payment_succeeded':
                invoice = event['data']['object']
                self.logger.info(f"Invoice payment succeeded: {invoice['id']}")
                return {
                    'status': 'processed',
                    'event_type': 'payment_succeeded',
                    'invoice_id': invoice['id'],
                    'subscription_id': invoice.get('subscription')
                }
            
            elif event['type'] == 'invoice.payment_failed':
                invoice = event['data']['object']
                self.logger.warning(f"Invoice payment failed: {invoice['id']}")
                return {
                    'status': 'processed',
                    'event_type': 'payment_failed',
                    'invoice_id': invoice['id'],
                    'subscription_id': invoice.get('subscription')
                }
            
            elif event['type'] == 'customer.subscription.deleted':
                subscription = event['data']['object']
                self.logger.info(f"Subscription cancelled: {subscription['id']}")
                return {
                    'status': 'processed',
                    'event_type': 'subscription_cancelled',
                    'subscription_id': subscription['id']
                }
            
            else:
                self.logger.info(f"Unhandled webhook event type: {event['type']}")
                return {'status': 'ignored', 'event_type': event['type']}
                
        except ValueError as e:
            self.logger.error(f"Invalid webhook payload: {str(e)}")
            return {'error': 'Invalid payload'}
        except stripe.error.SignatureVerificationError as e:
            self.logger.error(f"Invalid webhook signature: {str(e)}")
            return {'error': 'Invalid signature'}
        except Exception as e:
            self.logger.error(f"Webhook processing error: {str(e)}")
            return {'error': 'Webhook processing failed'}
    
    def get_subscription_status(self, subscription_id: str) -> Dict:
        """Get real Stripe subscription status"""
        if not subscription_id:
            return {'status': 'no_subscription'}
        
        if not self.stripe_secret_key:
            return {'status': 'error', 'error': 'Stripe not configured'}
        
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            return {
                'status': subscription.status,
                'current_period_start': datetime.fromtimestamp(subscription.current_period_start).isoformat(),
                'current_period_end': datetime.fromtimestamp(subscription.current_period_end).isoformat(),
                'plan_id': subscription.metadata.get('plan_id', 'unknown'),
                'billing_period': subscription.metadata.get('billing_period', 'monthly'),
                'customer_id': subscription.customer,
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'subscription_id': subscription.id
            }
            
        except stripe.error.StripeError as e:
            self.logger.error(f"Error retrieving subscription: {str(e)}")
            return {'status': 'error', 'error': f'Failed to retrieve subscription: {str(e)}'}
        except Exception as e:
            self.logger.error(f"Error getting subscription status: {str(e)}")
            return {'status': 'error', 'error': 'Failed to get subscription status'}
    
    def cancel_subscription(self, subscription_id: str) -> Dict:
        """Cancel a Stripe subscription"""
        if not self.stripe_secret_key:
            return {'error': 'Stripe not configured'}
        
        try:
            subscription = stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True
            )
            
            return {
                'status': 'success',
                'subscription_id': subscription.id,
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'current_period_end': datetime.fromtimestamp(subscription.current_period_end).isoformat()
            }
            
        except stripe.error.StripeError as e:
            self.logger.error(f"Error cancelling subscription: {str(e)}")
            return {'error': f'Failed to cancel subscription: {str(e)}'}
        except Exception as e:
            self.logger.error(f"Error cancelling subscription: {str(e)}")
            return {'error': 'Failed to cancel subscription'}

class SecurityAuditLogger:
    """Enhanced security logging for billing operations"""
    
    def __init__(self, security_core):
        self.security_core = security_core
    
    def log_payment_attempt(self, user_id: str, plan_id: str, amount: int, success: bool):
        """Log payment attempts for security monitoring"""
        event_type = 'payment_success' if success else 'payment_failed'
        severity = 'info' if success else 'warning'
        description = f"Payment attempt for {plan_id} plan: ${amount/100:.2f}"
        
        self.security_core.log_security_event(
            user_id, event_type, severity, description
        )
    
    def log_plan_change(self, user_id: str, old_plan: str, new_plan: str):
        """Log subscription plan changes"""
        description = f"Plan changed from {old_plan} to {new_plan}"
        self.security_core.log_security_event(
            user_id, 'plan_changed', 'info', description
        )
    
    def log_suspicious_billing_activity(self, user_id: str, activity: str):
        """Log suspicious billing activities"""
        self.security_core.log_security_event(
            user_id, 'suspicious_billing', 'high', f"Suspicious activity: {activity}"
        )

class DiscountEngine:
    """Handles all discount calculations and validations"""
    
    @staticmethod
    def calculate_auto_renewal_discount(base_price: int) -> int:
        """Calculate auto-renewal discount"""
        return 10  # $10 off for auto-renewal
    
    @staticmethod
    def calculate_yearly_savings(monthly_price: int) -> int:
        """Calculate savings for yearly billing (2 months free)"""
        return monthly_price * 2
    
    @staticmethod
    def calculate_trial_conversion_discount(price: int, billing_period: str, 
                                          trial_start: datetime) -> Tuple[int, bool]:
        """Calculate 25% trial conversion discount"""
        days_since_trial = (datetime.now() - trial_start).days
        
        if days_since_trial > 15:
            return 0, False
        
        if billing_period == 'yearly':
            return int(price * 0.25), True
        else:
            # 25% off first 3 months for monthly plans
            return int(price * 0.25 * 3), True
    
    @staticmethod
    def get_discount_summary(plan_id: str, billing_period: str, 
                           trial_start: datetime = None) -> Dict:
        """Get comprehensive discount summary"""
        billing_manager = BillingManager()
        pricing = billing_manager.get_plan_pricing()
        
        base_monthly = pricing[plan_id]['monthly'] + 10  # Add back auto-renewal discount
        discounted_monthly = base_monthly - 10
        
        discounts = [f"${10} auto-renewal savings"]
        total_savings = 10
        
        if billing_period == 'yearly':
            yearly_savings = DiscountEngine.calculate_yearly_savings(discounted_monthly)
            discounts.append(f"2 months FREE (save ${yearly_savings}/year)")
            total_savings += yearly_savings
            
            if trial_start:
                trial_discount, eligible = DiscountEngine.calculate_trial_conversion_discount(
                    pricing[plan_id]['yearly'], billing_period, trial_start
                )
                if eligible:
                    discounts.append(f"25% trial conversion (save ${trial_discount})")
                    total_savings += trial_discount
        
        return {
            'discounts': discounts,
            'total_savings': total_savings,
            'final_monthly_price': discounted_monthly,
            'final_yearly_price': pricing[plan_id]['yearly'] if billing_period == 'yearly' else None
        }
