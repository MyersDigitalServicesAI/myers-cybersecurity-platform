# app.py
import streamlit as st
import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables at the very beginning

# Import new/renamed modules
from security_core_pg import SecurityCore # Updated import
from payment import PaymentProcessor # New import
from billing import BillingManager # New import (though mostly for webhook_handler.py, included for completeness if app used billing_manager methods directly)
from email_automation import EmailAutomation, EmailEventHandler
from setup_wizard import SetupWizard
from signup_and_email_verification import show_signup_page, show_email_verification_page, show_awaiting_verification_page # New import
from thret_detection_dashboard import show_threat_detection_dashboard # New import
from admin_panel_module import show_admin_panel # New import

import logging
import pandas as pd # Needed for admin_panel_module

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up environment variables (if not already set in .env or system)
os.environ['DATABASE_URL'] = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost:5432/mydatabase')
os.environ['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY', 'sk_test_YOUR_STRIPE_SECRET_KEY')
os.environ['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_YOUR_STRIPE_WEBHOOK_SIGNING_SECRET')
os.environ['SENDER_EMAIL'] = os.getenv('SENDER_EMAIL', 'noreply@yourdomain.com')
os.environ['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.sendgrid.net')
os.environ['SMTP_PORT'] = os.getenv('SMTP_PORT', '587')
os.environ['SMTP_USER'] = os.getenv('SMTP_USER', 'apikey')
os.environ['SMTP_API_KEY'] = os.getenv('SMTP_API_KEY', 'SG.YOUR_ACTUAL_SENDGRID_API_KEY')
os.environ['APP_URL'] = os.getenv('APP_URL', 'http://localhost:8501')
os.environ['SETUP_ADMIN_EMAIL'] = os.getenv("SETUP_ADMIN_EMAIL", "admin@yourcompany.com") # Added for explicit access

def show_login_page():
    st.markdown("## Login to Myers Cybersecurity")
    with st.form("login_form"):
        email = st.text_input("Email Address")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", type="primary")

        if submitted:
            if email and password:
                user_auth_result, error_message = st.session_state.security_core.authenticate_user(email, password)

                if user_auth_result:
                    user_details = st.session_state.security_core.get_user_details(user_auth_result['id'])
                    if user_details and user_details.get('email_verified'):
                        st.session_state.authenticated = True
                        st.session_state.user_id = user_auth_result['id']
                        st.session_state.user_email = user_details['email']
                        st.session_state.user_role = user_details['role']
                        st.session_state.company_name = user_details['company']
                        st.session_state.selected_plan = user_details['plan']
                        st.session_state.first_name = user_details['first_name']
                        st.session_state.last_name = user_details['last_name']
                        st.success("Login successful!")
                        st.session_state.current_page = 'dashboard'
                        st.rerun()
                    elif user_details and not user_details.get('email_verified'):
                        st.warning("Your email address is not verified. Please check your inbox for the verification link.")
                        st.session_state.pending_verification = {"user_id": user_details['id'], "email": user_details['email']}
                        st.session_state.current_page = "awaiting_verification"
                        st.rerun()
                else:
                    st.error(error_message or "Invalid email or password.")
            else:
                st.error("Please enter both email and password.")
    st.markdown("---")
    st.write("Don't have an account?")
    if st.button("Sign Up Now", key="go_to_signup"):
        st.session_state.current_page = "signup"
        st.rerun()


def main():
    st.set_page_config(page_title="Myers Cybersecurity", page_icon="🔒", layout="wide")

    if 'security_core' not in st.session_state:
        try:
            st.session_state.security_core = SecurityCore()
        except Exception as e:
            st.error(f"Failed to initialize SecurityCore: {e}. Please check DATABASE_URL.")
            st.stop()
    
    if 'payment_processor' not in st.session_state:
        try:
            st.session_state.payment_processor = PaymentProcessor()
        except Exception as e:
            st.warning(f"Failed to initialize PaymentProcessor: {e}. Payment features might be unavailable.")
            st.session_state.payment_processor = None

    if 'email_automation' not in st.session_state:
        try:
            st.session_state.email_automation = EmailAutomation()
        except Exception as e:
            st.warning(f"Failed to initialize EmailAutomation: {e}. Email sending might be unavailable.")
            st.session_state.email_automation = None

    if 'email_event_handler' not in st.session_state and st.session_state.email_automation:
        st.session_state.email_event_handler = EmailEventHandler(
            st.session_state.security_core, st.session_state.email_automation
        )

    query_params = st.query_params
    if query_params.get("page") == "verify":
        st.session_state.current_page = "verify"
    elif "current_page" not in st.session_state:
        st.session_state.current_page = "home"

    st.sidebar.title("Navigation")
    if st.session_state.get('authenticated'):
        st.sidebar.markdown(f"**Logged in as:** {st.session_state.user_email}")
        st.sidebar.markdown(f"**Role:** {st.session_state.user_role.title()}")
        st.sidebar.markdown("---")
        st.sidebar.button("Dashboard", on_click=lambda: st.session_state.update(current_page='dashboard'), use_container_width=True)
        st.sidebar.button("Threat Intelligence", on_click=lambda: st.session_state.update(current_page='threat_intelligence'), use_container_width=True)
        st.sidebar.button("My API Keys", on_click=lambda: st.session_state.update(current_page='api_keys'), use_container_width=True)
        st.sidebar.button("Subscription", on_click=lambda: st.session_state.update(current_page='subscription'), use_container_width=True)
        if st.session_state.user_role == 'admin': # Admin panel only for admins
            st.sidebar.button("Admin Panel", on_click=lambda: st.session_state.update(current_page='admin_panel'), use_container_width=True)
        st.sidebar.button("Logout", on_click=lambda: [st.session_state.clear(), st.session_state.update(current_page='home')], use_container_width=True)
    else:
        if st.sidebar.button("Home", use_container_width=True):
            st.session_state.current_page = 'home'
            if 'setup_step' in st.session_state:
                del st.session_state.setup_step
            st.rerun()
        if st.sidebar.button("Sign Up", use_container_width=True):
            st.session_state.current_page = "signup"
            st.rerun()
        if st.sidebar.button("Login", use_container_width=True):
            st.session_state.current_page = "login"
            st.rerun()

    admin_user_exists = False
    try:
        user = st.session_state.security_core.get_user_by_email(os.getenv("SETUP_ADMIN_EMAIL"))
        if user and user.get('role') == 'admin':
            admin_user_exists = True
    except Exception as e:
        logger.error(f"Error checking for admin user during app startup: {e}", exc_info=True)

    if not admin_user_exists and not st.session_state.get('initial_setup_done', False):
        st.session_state.current_page = "setup_wizard"


    if st.session_state.current_page == "home":
        st.title("Welcome to Myers Cybersecurity Platform")
        st.write("Secure your enterprise with our comprehensive API security and management solution.")
        st.image("https://via.placeholder.com/600x300?text=Myers+Cybersecurity+Logo", use_column_width=True)
        st.markdown("### Get Started")
        st.write("To begin securing your API keys and systems, you can start a free trial or log in.")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Free Trial", type="primary", use_container_width=True):
                st.session_state.current_page = "signup"
                st.rerun()
        with col2:
            if st.button("Existing User? Login", use_container_width=True):
                st.session_state.current_page = "login"
                st.rerun()

        st.markdown("---")
        st.subheader("Key Features:")
        st.markdown("""
        - **Centralized API Key Management**: Securely store, rotate, and manage all your API keys.
        - **Real-time Threat Monitoring**: Detect and alert on suspicious API usage and anomalies.
        - **Automated Security Scanning**: Proactively identify vulnerabilities in your API infrastructure.
        - **Compliance Reporting**: Generate reports for SOC 2, GDPR, HIPAA, and more.
        - **User & Access Management**: Control who has access to your sensitive API keys and data.
        """)

    elif st.session_state.current_page == "signup":
        show_signup_page(st.session_state.security_core, st.session_state.email_automation)

    elif st.session_state.current_page == "verify":
        if st.session_state.email_event_handler:
            show_email_verification_page(st.session_state.security_core, st.session_state.email_event_handler)
        else:
            st.error("Email verification service not available. Please contact support.")

    elif st.session_state.current_page == "awaiting_verification":
        if st.session_state.email_automation:
            show_awaiting_verification_page(st.session_state.security_core, st.session_state.email_automation)
        else:
            st.error("Email sending service not available for resending verification. Please contact support.")

    elif st.session_state.current_page == "login":
        show_login_page()

    elif st.session_state.current_page == "setup_wizard":
        try:
            setup_wizard = SetupWizard(st.session_state.security_core)
            setup_wizard.show_setup_wizard()
        except Exception as e:
            st.error(f"Error initializing setup wizard: {e}. Please ensure your DATABASE_URL is correctly configured and accessible.")
            st.info("Example DATABASE_URL format: `postgresql://user:password@host:port/database_name`")

    elif st.session_state.current_page == "dashboard":
        if st.session_state.get('authenticated'):
            st.title(f"Welcome, {st.session_state.first_name}!")
            st.subheader(f"Company: {st.session_state.company_name}")
            st.write(f"You are logged in as **{st.session_state.user_email}** ({st.session_state.user_role}).")
            st.write(f"Your current plan: **{st.session_state.selected_plan.title()}**")

            st.success("Your Myers Cybersecurity platform is now active and ready for use!")
            st.markdown("""
            Explore your dashboard to:
            - Manage API keys
            - View security logs
            - Configure alerts
            - Add team members
            - Access support resources
            """)

            user_details = st.session_state.security_core.get_user_details(st.session_state.user_id)
            if user_details:
                st.info(f"**Account Status:** {user_details.get('payment_status', 'Unknown').replace('_', ' ').title()}")
                if user_details.get('is_trial'):
                    st.warning(f"Your free trial ends on: {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
                elif user_details.get('payment_status') == 'active':
                    st.success(f"Next billing date: {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
                elif user_details.get('payment_status') == 'failed' or user_details.get('payment_status') == 'past_due':
                    st.error("Your payment is overdue. Please update your payment method to avoid service interruption.")
                    if st.button("Manage Subscription"):
                        st.session_state.current_page = "subscription"
                        st.rerun()

            st.subheader("Quick Actions")
            col_dash1, col_dash2 = st.columns(2)
            with col_dash1:
                if st.button("View Threat Dashboard", use_container_width=True):
                    st.session_state.current_page = "threat_intelligence"
                    st.rerun()
            with col_dash2:
                if st.button("Manage My API Keys", use_container_width=True):
                    st.session_state.current_page = "api_keys"
                    st.rerun()

        else:
            st.warning("Please log in to view the dashboard.")
            st.session_state.current_page = "login"
            st.rerun()
            
    elif st.session_state.current_page == "threat_intelligence":
        if st.session_state.get('authenticated'):
            show_threat_detection_dashboard(st.session_state.security_core)
        else:
            st.warning("Please log in to view the Threat Intelligence Dashboard.")
            st.session_state.current_page = "login"
            st.rerun()

    elif st.session_state.current_page == "api_keys":
        if st.session_state.get('authenticated'):
            st.title("My API Keys")
            st.write("Manage your API keys here.")
            
            with st.expander("Add New API Key"):
                with st.form("new_api_key_form"):
                    key_name = st.text_input("Key Name", help="A descriptive name for this API key (e.g., 'Website Integration Key')")
                    key_service = st.text_input("Service/Application", help="The service or application that will use this key (e.g., 'Internal CRM', 'External API')")
                    key_permissions = st.selectbox("Permissions", ["read", "read-write", "admin"], help="Define access level for this key")
                    generate_button = st.form_submit_button("Generate New Key", type="primary")

                    if generate_button:
                        if key_name and key_service:
                            new_api_key_value = secrets.token_urlsafe(32)
                            try:
                                key_id = st.session_state.security_core.add_api_key(
                                    user_id=st.session_state.user_id,
                                    name=key_name,
                                    api_key=new_api_key_value,
                                    service=key_service,
                                    permissions=key_permissions
                                )
                                if key_id:
                                    st.success(f"API Key '{key_name}' generated successfully!")
                                    st.code(f"Your New API Key: {new_api_key_value}")
                                    st.warning("Please copy this key now. It will not be shown again for security reasons.")
                                    st.rerun()
                                else:
                                    st.error("Failed to generate API key.")
                            except Exception as e:
                                st.error(f"An error occurred while generating API key: {e}")
                        else:
                            st.error("Please provide a name and service for the new API key.")

            st.markdown("---")
            st.subheader("Your Existing API Keys")
            try:
                user_api_keys = st.session_state.security_core.get_user_api_keys(st.session_state.user_id)
                if user_api_keys:
                    for key in user_api_keys:
                        st.json({
                            "ID": key['id'],
                            "Name": key['name'],
                            "Service": key['service'],
                            "Permissions": key['permissions'],
                            "Created At": key['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                            "Status": key['status']
                        })
                        col_key1, col_key2 = st.columns(2)
                        with col_key1:
                            if st.button(f"Revoke {key['name']}", key=f"revoke_{key['id']}"):
                                st.warning("Revoke functionality not yet implemented.")
                        with col_key2:
                            if st.button(f"Rotate {key['name']}", key=f"rotate_{key['id']}"):
                                st.warning("Rotate functionality not yet implemented.")
                        st.markdown("---")
                else:
                    st.info("You don't have any API keys yet. Use the form above to generate one!")
            except Exception as e:
                st.error(f"Could not load API keys: {e}")

        else:
            st.warning("Please log in to manage your API keys.")
            st.session_state.current_page = "login"
            st.rerun()

    elif st.session_state.current_page == "subscription":
        if st.session_state.get('authenticated'):
            st.title("My Subscription")
            user_details = st.session_state.security_core.get_user_details(st.session_state.user_id)
            if user_details:
                st.subheader(f"Current Plan: {user_details.get('plan', 'N/A').title()}")
                st.info(f"Payment Status: **{user_details.get('payment_status', 'N/A').replace('_', ' ').title()}**")
                
                if user_details.get('is_trial'):
                    st.warning(f"Your free trial is active and ends on: {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
                    st.markdown("### Upgrade Your Plan!")
                    st.write("Ready to secure your operations beyond the trial? Choose a plan below to subscribe.")

                    stripe_price_ids = {
                        "basic_monthly": "price_1P6j0v...", # Replace with actual
                        "professional_monthly": "price_1P6j0z...", # Replace with actual
                        "business_yearly": "price_1P6j10..." # Replace with actual
                    }

                    col_plans = st.columns(3)
                    with col_plans[0]:
                        st.subheader("Basic Plan")
                        st.write("Monthly: $20/month")
                        if st.button("Subscribe Basic (Monthly)", key="sub_basic_m"):
                            if st.session_state.payment_processor:
                                success_url = f"{APP_URL}/?page=dashboard&payment=success"
                                cancel_url = f"{APP_URL}/?page=subscription&payment=cancelled"
                                checkout = st.session_state.payment_processor.create_checkout_session(
                                    stripe_price_ids.get("basic_monthly"), user_details['email'], success_url, cancel_url
                                )
                                if checkout.get('checkout_url'):
                                    st.session_state.checkout_url = checkout['checkout_url']
                                    st.markdown(f'[Click here to complete payment]({checkout["checkout_url"]})')
                                    st.success("Redirecting to Stripe Checkout...")
                                else:
                                    st.error(f"Failed to create checkout session: {checkout.get('error', 'Unknown error')}")
                            else:
                                st.error("Payment processor not initialized.")

                    with col_plans[1]:
                        st.subheader("Professional Plan")
                        st.write("Monthly: $50/month")
                        if st.button("Subscribe Professional (Monthly)", key="sub_prof_m"):
                            if st.session_state.payment_processor:
                                success_url = f"{APP_URL}/?page=dashboard&payment=success"
                                cancel_url = f"{APP_URL}/?page=subscription&payment=cancelled"
                                checkout = st.session_state.payment_processor.create_checkout_session(
                                    stripe_price_ids.get("professional_monthly"), user_details['email'], success_url, cancel_url
                                )
                                if checkout.get('checkout_url'):
                                    st.session_state.checkout_url = checkout['checkout_url']
                                    st.markdown(f'[Click here to complete payment]({checkout["checkout_url"]})')
                                    st.success("Redirecting to Stripe Checkout...")
                                else:
                                    st.error(f"Failed to create checkout session: {checkout.get('error', 'Unknown error')}")
                            else:
                                st.error("Payment processor not initialized.")

                    with col_plans[2]:
                        st.subheader("Business Plan")
                        st.write("Yearly: $500/year")
                        if st.button("Subscribe Business (Yearly)", key="sub_biz_y"):
                            if st.session_state.payment_processor:
                                success_url = f"{APP_URL}/?page=dashboard&payment=success"
                                cancel_url = f"{APP_URL}/?page=subscription&payment=cancelled"
                                checkout = st.session_state.payment_processor.create_checkout_session(
                                    stripe_price_ids.get("business_yearly"), user_details['email'], success_url, cancel_url
                                )
                                if checkout.get('checkout_url'):
                                    st.session_state.checkout_url = checkout['checkout_url']
                                    st.markdown(f'[Click here to complete payment]({checkout["checkout_url"]})')
                                    st.success("Redirecting to Stripe Checkout...")
                                else:
                                    st.error(f"Failed to create checkout session: {checkout.get('error', 'Unknown error')}")
                            else:
                                st.error("Payment processor not initialized.")

                elif user_details.get('payment_status') == 'active':
                    st.success("You have an active subscription!")
                    st.write(f"Your next billing date is: {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
                    st.write(f"Your Stripe Subscription ID: `{user_details.get('subscription_id', 'N/A')}`")
                    
                    st.markdown("---")
                    st.subheader("Manage Your Subscription")
                    st.write("You can manage your billing information, download invoices, or cancel your subscription via the Stripe Customer Portal.")
                    
                    if st.button("Go to Customer Portal"):
                        st.warning("Customer Portal integration requires a backend endpoint to generate a portal session URL.")

                elif user_details.get('payment_status') == 'failed' or user_details.get('payment_status') == 'past_due':
                    st.error("Your subscription payment has failed or is past due. Please update your payment method.")
                    if st.button("Update Payment Method (Go to Customer Portal)"):
                        st.warning("Customer Portal integration required here.")
                
                elif user_details.get('payment_status') == 'cancelled':
                    st.info("Your subscription has been cancelled.")
                    st.write("You can reactivate or choose a new plan below.")
                    if st.button("Reactivate / Choose New Plan"):
                        st.session_state.current_page = "subscription"
                        st.rerun()

            else:
                st.error("Could not retrieve your subscription details.")
        else:
            st.warning("Please log in to manage your subscription.")
            st.session_state.current_page = "login"
            st.rerun()

    elif st.session_state.current_page == "admin_panel":
        if st.session_state.get('authenticated') and st.session_state.user_role == 'admin':
            show_admin_panel(st.session_state.security_core)
        else:
            st.error("Access Denied: You do not have permission to view the Admin Panel.")
            st.session_state.current_page = "dashboard" # Redirect non-admins
            st.rerun()


if __name__ == "__main__":
    main()
