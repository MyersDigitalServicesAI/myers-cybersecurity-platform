import streamlit as st
import os
import secrets # Added for generating secure API keys
from dotenv import load_dotenv
import logging
import pandas as pd # Needed for admin_panel_module
from datetime import datetime # Added for password reset expiry

load_dotenv() # Load environment variables at the very beginning

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Set up environment variables (if not already set in .env or system) ---
# These defaults are for development; replace with actual values for production.
os.environ['DATABASE_URL'] = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost:5432/mydatabase')
os.environ['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY', 'sk_test_YOUR_STRIPE_SECRET_KEY')
os.environ['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_YOUR_STRIPE_WEBHOOK_SIGNING_SECRET')
os.environ['SENDER_EMAIL'] = os.getenv('SENDER_EMAIL', 'noreply@yourdomain.com')
os.environ['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.sendgrid.net')
os.environ['SMTP_PORT'] = os.getenv('SMTP_PORT', '587')
os.environ['SMTP_USER'] = os.getenv('SMTP_USER', 'apikey')
os.environ['SMTP_API_KEY'] = os.getenv('SMTP_API_KEY', 'SG.YOUR_ACTUAL_SENDGRID_API_KEY')
os.environ['APP_URL'] = os.getenv('APP_URL', 'http://localhost:8501')
os.environ['SETUP_ADMIN_EMAIL'] = os.getenv("SETUP_ADMIN_EMAIL", "admin@yourcompany.com")

# --- Import modules ---
# Assuming SecurityCorePG has been updated to use connection pooling internally
from security_core_pg import SecurityCorePG as SecurityCore # Renamed for clarity in imports
from payment import PaymentProcessor
from billing import BillingManager # Still relevant if app ever directly calls methods from it
from email_automation import EmailAutomation, EmailEventHandler
from setup_wizard import SetupWizard
from signup_and_email_verification import show_signup_page, show_email_verification_page, show_awaiting_verification_page
# Corrected typo:
from threat_detection_dashboard import show_threat_detection_dashboard
from admin_panel_module import show_admin_panel

# --- Streamlit Caching for Services ---
# Initialize services only once for the entire Streamlit app lifecycle.
# This ensures database connection pooling works correctly across reruns.
@st.cache_resource(ttl=None) # ttl=None means cache forever or until app restarts
def get_security_core_instance():
    # init_db_pool() should be called inside SecurityCorePG's constructor or a dedicated utils.database.init_db_pool()
    # Ensure your SecurityCorePG's __init__ calls init_db_pool from utils.database.
    return SecurityCore()

@st.cache_resource(ttl=None)
def get_payment_processor_instance():
    return PaymentProcessor()

@st.cache_resource(ttl=None)
def get_email_automation_instance():
    return EmailAutomation()

# --- Page Functions ---

# --- Password Reset Functions (New) ---
def forgot_password_page(security_core_instance: SecurityCore, email_automation_instance: EmailAutomation):
    st.title("Forgot Your Password?")
    st.write("Enter your email address to receive a password reset link.")

    email = st.text_input("Email Address", key="forgot_email_input")

    if st.button("Send Reset Link", key="send_reset_link_button", type="primary"):
        if email:
            with st.spinner("Sending password reset link..."):
                try:
                    token = security_core_instance.generate_password_reset_token(email)
                    if token:
                        app_base_url = os.getenv('APP_URL', 'http://localhost:8501')
                        reset_link = f"{app_base_url}/?page=reset_password&token={token}"
                        
                        email_sent = email_automation_instance.send_password_reset_email(email, reset_link)
                        if email_sent:
                            st.success("A password reset link has been sent to your email address. Please check your inbox (and spam folder).")
                            st.toast("Reset link sent!", icon="✅")
                        else:
                            st.error("Failed to send the password reset email. Please try again later.")
                            st.toast("Email failed!", icon="❌")
                    else:
                        st.error("Could not generate a reset link for this email. Please ensure the email is registered.")
                        st.toast("Email not found!", icon="⚠️")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")
                    logger.error(f"Error in forgot_password_page for {email}: {e}", exc_info=True)
                    st.toast("Error occurred!", icon="❌")
        else:
            st.warning("Please enter your email address.")

def reset_password_page(security_core_instance: SecurityCore):
    st.title("Reset Your Password")
    query_params = st.experimental_get_query_params()
    token = query_params.get("token", [None])[0]

    if not token:
        st.error("Invalid or missing password reset token. Please request a new one.")
        st.info("You can request a new password reset link from the login page.")
        return

    # Verify token
    user_info = security_core_instance.verify_password_reset_token(token)
    if not user_info:
        st.error("This password reset link is invalid or has expired. Please request a new one.")
        st.info("If you just requested a link, it might have been used or expired. Request a new one.")
        return

    st.info(f"Resetting password for: **{user_info['email']}**")
    new_password = st.text_input("New Password", type="password", key="new_password_reset_input")
    confirm_password = st.text_input("Confirm New Password", type="password", key="confirm_password_reset_input")

    if st.button("Reset Password", key="reset_password_button", type="primary"):
        if new_password and confirm_password:
            if new_password == confirm_password:
                if len(new_password) < 8:
                    st.error("Password must be at least 8 characters long.")
                else:
                    with st.spinner("Resetting your password..."):
                        try:
                            if security_core_instance.reset_user_password(user_info['user_id'], new_password):
                                st.success("Your password has been reset successfully! You can now log in.")
                                st.balloons()
                                # Clear query params to prevent token re-use
                                st.experimental_set_query_params() 
                                st.session_state['current_page'] = 'login'
                                st.rerun()
                            else:
                                st.error("Failed to reset password. Please try again.")
                        except Exception as e:
                            st.error(f"An unexpected error occurred during password reset: {e}")
                            logger.error(f"Error resetting password for user {user_info['user_id']}: {e}", exc_info=True)
            else:
                st.error("Passwords do not match.")
        else:
            st.warning("Please fill in both password fields.")


def show_login_page():
    st.markdown("## Login to Myers Cybersecurity")
    with st.form("login_form"):
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Login", type="primary")

        if submitted:
            if email and password:
                with st.spinner("Logging in..."):
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
                    st.toast("Login failed!", icon="❌")
            else:
                st.error("Please enter both email and password.")
                st.toast("Missing credentials!", icon="⚠️")
    st.markdown("---")
    st.write("Don't have an account?")
    if st.button("Sign Up Now", key="go_to_signup"):
        st.session_state.current_page = "signup"
        st.rerun()
    if st.button("Forgot Password?", key="go_to_forgot_password"): # Added Forgot Password button
        st.session_state.current_page = "forgot_password"
        st.rerun()


def main():
    st.set_page_config(page_title="Myers Cybersecurity", page_icon="🔒", layout="wide")

    # --- Initialize Services (using cached instances) ---
    st.session_state.security_core = get_security_core_instance()
    st.session_state.payment_processor = get_payment_processor_instance()
    st.session_state.email_automation = get_email_automation_instance()

    if st.session_state.email_automation:
        st.session_state.email_event_handler = EmailEventHandler(
            st.session_state.security_core, st.session_state.email_automation
        )
    else:
        st.session_state.email_event_handler = None # Ensure it's None if email_automation failed


    # --- Handle Query Parameters for Email Verification and Password Reset ---
    query_params = st.query_params
    if query_params.get("page") == "verify":
        st.session_state.current_page = "verify"
    elif query_params.get("page") == "reset_password": # New: Handle reset password page
        st.session_state.current_page = "reset_password"
    elif "current_page" not in st.session_state:
        st.session_state.current_page = "home"

    # --- Sidebar Navigation ---
    st.sidebar.title("Navigation")
    if st.session_state.get('authenticated'):
        st.sidebar.markdown(f"**Logged in as:** {st.session_state.user_email}")
        st.sidebar.markdown(f"**Role:** {st.session_state.user_role.title()}")
        st.sidebar.markdown("---")
        st.sidebar.button("Dashboard", on_click=lambda: st.session_state.update(current_page='dashboard'), use_container_width=True)
        st.sidebar.button("Threat Intelligence", on_click=lambda: st.session_state.update(current_page='threat_intelligence'), use_container_width=True)
        st.sidebar.button("My API Keys", on_click=lambda: st.session_state.update(current_page='api_keys'), use_container_width=True)
        st.sidebar.button("Subscription", on_click=lambda: st.session_state.update(current_page='subscription'), use_container_width=True)
        if st.session_state.user_role == 'admin':
            st.sidebar.button("Admin Panel", on_click=lambda: st.session_state.update(current_page='admin_panel'), use_container_width=True)
        st.sidebar.button("Logout", on_click=lambda: [st.session_state.clear(), st.session_state.update(current_page='home')], use_container_width=True)
    else:
        # Public navigation
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

    # --- Initial Setup Wizard Check ---
    admin_user_exists = False
    try:
        user = st.session_state.security_core.get_user_by_email(os.getenv("SETUP_ADMIN_EMAIL"))
        if user and user.get('role') == 'admin':
            admin_user_exists = True
    except Exception as e:
        logger.error(f"Error checking for admin user during app startup: {e}", exc_info=True)

    if not admin_user_exists and not st.session_state.get('initial_setup_done', False):
        st.session_state.current_page = "setup_wizard"

    # --- Page Routing ---
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

    elif st.session_state.current_page == "forgot_password": # New: Forgot Password Page
        forgot_password_page(st.session_state.security_core, st.session_state.email_automation)

    elif st.session_state.current_page == "reset_password": # New: Reset Password Page
        reset_password_page(st.session_state.security_core)

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
                    # Assuming 'trial_ends' is re-purposed for 'next_billing_date' or similar after trial
                    st.success(f"Next billing date: {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
                elif user_details.get('payment_status') in ['failed', 'past_due']:
                    st.error("Your payment is overdue. Please update your payment method to avoid service interruption.")
                    if st.button("Manage Subscription (Update Payment Method)"):
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
            # Corrected typo in function call
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
                    key_name = st.text_input("Key Name", help="A descriptive name for this API key (e.g., 'Website Integration Key')", key="new_key_name")
                    key_service = st.text_input("Service/Application", help="The service or application that will use this key (e.g., 'Internal CRM', 'External API')", key="new_key_service")
                    key_permissions = st.selectbox("Permissions", ["read", "read-write", "admin"], help="Define access level for this key", key="new_key_permissions")
                    generate_button = st.form_submit_button("Generate New Key", type="primary")

                    if generate_button:
                        if key_name and key_service:
                            new_api_key_value = secrets.token_urlsafe(32)
                            try:
                                with st.spinner("Generating new API key..."):
                                    key_info = st.session_state.security_core.add_api_key(
                                        user_id=st.session_state.user_id,
                                        name=key_name,
                                        api_key=new_api_key_value,
                                        service=key_service,
                                        permissions=key_permissions
                                    )
                                if key_info and 'api_key_id' in key_info: # Ensure key_info contains the ID
                                    st.success(f"API Key '{key_name}' generated successfully!")
                                    st.code(f"Your New API Key: {new_api_key_value}")
                                    st.warning("Please copy this key now. It will not be shown again for security reasons.")
                                    st.rerun()
                                else:
                                    st.error("Failed to generate API key.")
                                    st.toast("Key generation failed!", icon="❌")
                            except Exception as e:
                                st.error(f"An error occurred while generating API key: {e}")
                                logger.error(f"Error generating API key for user {st.session_state.user_id}: {e}", exc_info=True)
                                st.toast("Error generating key!", icon="❌")
                        else:
                            st.error("Please provide a name and service for the new API key.")
                            st.toast("Missing key details!", icon="⚠️")

            st.markdown("---")
            st.subheader("Your Existing API Keys")
            try:
                user_api_keys = st.session_state.security_core.get_user_api_keys(st.session_state.user_id)
                if user_api_keys:
                    for key in user_api_keys:
                        status_color = "green" if key['is_active'] else "red"
                        st.markdown(f"#### {key['name']} ({'Active' if key['is_active'] else 'Inactive'})")
                        st.json({
                            "ID": key['api_key_id'],
                            "Service": key['service'],
                            "Permissions": key['permissions'],
                            "Created At": key['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                            "Last Used": key['last_used_at'].strftime('%Y-%m-%d %H:%M:%S') if key['last_used_at'] else 'Never',
                            "Revoked At": key['revoked_at'].strftime('%Y-%m-%d %H:%M:%S') if key['revoked_at'] else 'N/A'
                        })
                        col_key1, col_key2 = st.columns(2)
                        with col_key1:
                            if key['is_active']:
                                if st.button(f"Revoke {key['name']}", key=f"revoke_{key['api_key_id']}", type="secondary"):
                                    with st.spinner(f"Revoking API key {key['name']}..."):
                                        admin_user_id = st.session_state.get('user_id')
                                        success = st.session_state.security_core.revoke_api_key(key['api_key_id'], admin_user_id)
                                        if success:
                                            st.success("API Key revoked successfully!")
                                            st.toast("Key revoked!", icon="✅")
                                            st.rerun()
                                        else:
                                            st.error("Failed to revoke API Key.")
                                            st.toast("Revoke failed!", icon="❌")
                            else:
                                st.info("Key is already inactive.")
                        with col_key2:
                            if key['is_active']:
                                if st.button(f"Rotate {key['name']}", key=f"rotate_{key['api_key_id']}", type="secondary"):
                                    with st.spinner(f"Rotating API key {key['name']}..."):
                                        admin_user_id = st.session_state.get('user_id')
                                        new_key_string = st.session_state.security_core.rotate_api_key(key['api_key_id'], admin_user_id)
                                        if new_key_string:
                                            st.success(f"API Key rotated successfully! New Key: `{new_key_string}`")
                                            st.info("Please copy this new key now. It will not be shown again for security reasons.")
                                            st.toast("Key rotated!", icon="✅")
                                            st.rerun()
                                        else:
                                            st.error("Failed to rotate API Key.")
                                            st.toast("Rotate failed!", icon="❌")
                            else:
                                st.warning("Cannot rotate an inactive key. Consider generating a new one.")
                        st.markdown("---")
                else:
                    st.info("You don't have any API keys yet. Use the form above to generate one!")
            except Exception as e:
                st.error(f"Could not load API keys: {e}")
                logger.error(f"Error loading API keys for user {st.session_state.user_id}: {e}", exc_info=True)
                st.toast("Error loading keys!", icon="❌")

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
                
                # Fetch active Stripe prices dynamically
                st.markdown("---")
                st.subheader("Available Plans")
                available_plans_data = st.session_state.payment_processor.get_active_prices()
                
                if available_plans_data and "prices" in available_plans_data:
                    # Filter and sort prices by your preferred logic (e.g., by product name or amount)
                    # This example assumes products have names like 'Basic', 'Professional', 'Business'
                    plans_for_display = {}
                    for price in available_plans_data['prices']:
                        if price.product and price.product.name:
                            # You might need more sophisticated mapping if product names are not clean
                            plans_for_display[price.product.name] = {
                                'price_id': price.id,
                                'amount': price.unit_amount / 100 if price.unit_amount else 'N/A', # Convert cents to dollars
                                'interval': price.recurring.interval if price.recurring else 'one-time'
                            }
                    
                    if not plans_for_display:
                        st.warning("No active plans found on Stripe. Please configure plans in your Stripe dashboard.")
                    else:
                        col_plans = st.columns(len(plans_for_display))
                        plan_names = list(plans_for_display.keys())
                        for i, plan_name in enumerate(plan_names):
                            plan_info = plans_for_display[plan_name]
                            with col_plans[i]:
                                st.markdown(f"#### {plan_name}")
                                st.write(f"**Price:** ${plan_info['amount']}/{plan_info['interval']}")
                                if st.button(f"Select {plan_name}", key=f"select_plan_{plan_info['price_id']}", type="primary"):
                                    if st.session_state.payment_processor:
                                        success_url = f"{os.getenv('APP_URL')}/?page=dashboard&payment=success"
                                        cancel_url = f"{os.getenv('APP_URL')}/?page=subscription&payment=cancelled"
                                        
                                        with st.spinner(f"Initiating checkout for {plan_name}..."):
                                            checkout = st.session_state.payment_processor.create_checkout_session(
                                                plan_info['price_id'], user_details['email'], success_url, cancel_url
                                            )
                                            if checkout and checkout.get('checkout_url'):
                                                st.markdown(f'[Click here to complete payment]({checkout["checkout_url"]})')
                                                st.success("Redirecting to Stripe Checkout...")
                                                st.toast("Redirecting!", icon="🌐")
                                                # Optional: Redirect browser directly
                                                st.experimental_set_query_params(checkout_redirect=checkout['checkout_url'])
                                            else:
                                                st.error(f"Failed to create checkout session: {checkout.get('error', 'Unknown error')}")
                                                st.toast("Checkout failed!", icon="❌")
                                    else:
                                        st.error("Payment processor not initialized.")
                                        st.toast("Payment service error!", icon="❌")
                else:
                    st.error(f"Failed to load plans from Stripe: {available_plans_data.get('error', 'Unknown error')}")
                    st.toast("Stripe connection failed!", icon="❌")

                st.markdown("---")
                st.subheader("Manage Your Existing Subscription")
                
                # Customer Portal Integration (New)
                if user_details.get('stripe_customer_id'): # Check if user has a linked Stripe Customer ID
                    if st.button("Go to Stripe Customer Portal", key="go_to_customer_portal", type="secondary"):
                        with st.spinner("Creating Stripe Customer Portal session..."):
                            app_base_url = os.getenv('APP_URL', 'http://localhost:8501')
                            return_url = f"{app_base_url}/?page=subscription"
                            portal_result = st.session_state.payment_processor.create_customer_portal_session(
                                customer_id=user_details['stripe_customer_id'],
                                return_url=return_url
                            )
                            if portal_result and "portal_url" in portal_result:
                                st.success("Redirecting to Stripe Customer Portal!")
                                st.markdown(f"[Click here to open portal]({portal_result['portal_url']})", unsafe_allow_html=True)
                                st.toast("Opening portal!", icon="🚀")
                                # Optional: Redirect browser directly
                                st.experimental_set_query_params(portal_redirect=portal_result['portal_url'])
                            else:
                                st.error(f"Failed to create customer portal session: {portal_result.get('error', 'Unknown error')}")
                                st.toast("Portal failed!", icon="❌")
                else:
                    st.info("Your account is not yet linked to a Stripe customer ID. This usually happens after your first successful subscription.")
                    st.warning("If you believe this is an error, please contact support.")


            else:
                st.error("Could not retrieve your subscription details.")
                st.toast("Subscription details error!", icon="❌")
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
