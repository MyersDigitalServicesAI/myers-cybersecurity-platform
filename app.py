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
    # If init_db_pool is a global function in utils.database, call it explicitly here if not handled by SecurityCore init.
    # Example: from utils.database import init_db_pool; init_db_pool()
    return SecurityCore()

@st.cache_resource(ttl=None)
def get_payment_processor_instance():
    return PaymentProcessor()

@st.cache_resource(ttl=None)
def get_email_automation_instance():
    return EmailAutomation()

# --- Page Functions ---

# Placeholder for dashboard and subscription pages
def show_dashboard_page():
    st.title("Dashboard")
    st.write(f"Welcome, {st.session_state.first_name} {st.session_state.last_name} ({st.session_state.user_email})!")
    st.write(f"Your Company: {st.session_state.company_name}")
    st.write(f"Your Plan: {st.session_state.selected_plan.title()}")
    st.write("This is your main dashboard. More features will appear here based on your subscription.")

def show_subscription_page():
    st.title("Manage Your Subscription")
    st.write("Details about your current plan, billing, and options to upgrade or manage your subscription.")
    user_details = st.session_state.security_core.get_user_details(st.session_state.user_id)
    if user_details:
        st.write(f"**Current Plan:** {user_details.get('plan', 'N/A').title()}")
        st.write(f"**Payment Status:** {user_details.get('payment_status', 'N/A').replace('_', ' ').title()}")
        if user_details.get('is_trial'):
            st.write(f"**Trial Ends:** {user_details.get('trial_ends').strftime('%Y-%m-%d') if user_details.get('trial_ends') else 'N/A'}")
        if user_details.get('subscription_id'):
            st.write(f"**Subscription ID:** {user_details.get('subscription_id')}")
        st.write(f"**Auto-renewal:** {'Enabled' if user_details.get('auto_renewal') else 'Disabled'}")

        st.markdown("---")
        st.subheader("Billing Details")
        # In a real app, you'd fetch more detailed billing info from Stripe or your payment processor.
        st.info("Billing information will appear here.")
        
        # Example of displaying calculated prices (using the new function)
        # Assuming you have a way to get the base price for the user's plan
        # For demonstration, let's assume 'essentials' is $50, 'basic' is $100
        plan_prices = {
            'essentials': 50.0,
            'basic': 100.0,
            'professional': 200.0,
            'business': 500.0,
            'enterprise': 1000.0
        }
        
        user_plan = user_details.get('plan')
        user_billing_period = user_details.get('billing_period', 'monthly') # Assuming this field exists
        
        if user_plan and user_plan in plan_prices:
            base_price = plan_prices[user_plan]
            pricing_info = st.session_state.security_core.calculate_discounted_price(
                base_price, user_plan, user_billing_period, st.session_state.user_id
            )
            st.write("#### Your Current Plan Pricing Overview:")
            st.json(pricing_info)
        else:
            st.warning("Could not retrieve detailed pricing for your plan.")

    else:
        st.error("Could not load your subscription details.")

def show_api_keys_page():
    st.title("My API Keys")
    st.write("Manage your API keys for integrating with our services.")

    security_core = st.session_state.security_core
    user_id = st.session_state.user_id

    # Display existing API keys
    st.subheader("Existing API Keys")
    api_keys = security_core.list_api_keys(user_id)
    if api_keys:
        keys_data = []
        for key in api_keys:
            keys_data.append({
                "ID": key['id'],
                "Name": key['name'],
                "Service": key['service'],
                "Permissions": key['permissions'],
                "Created At": key['created_at'].strftime('%Y-%m-%d %H:%M') if key['created_at'] else 'N/A',
                "Last Used": key['last_used'].strftime('%Y-%m-%d %H:%M') if key['last_used'] else 'Never',
                "Status": key['status'].title()
            })
        st.dataframe(pd.DataFrame(keys_data), use_container_width=True)

        # Actions for existing keys
        st.markdown("---")
        st.subheader("Manage Existing Keys")
        col_select, col_action = st.columns([0.7, 0.3])
        
        selected_key_id = col_select.selectbox(
            "Select API Key to manage",
            options=[k['id'] for k in api_keys],
            format_func=lambda x: next((k['name'] for k in api_keys if k['id'] == x), x),
            key="manage_api_key_select"
        )

        if selected_key_id:
            selected_key_info = next((k for k in api_keys if k['id'] == selected_key_id), None)
            if selected_key_info:
                st.write(f"**Selected Key:** {selected_key_info['name']} (Status: {selected_key_info['status'].title()})")
                
                if selected_key_info['status'] == 'active':
                    if col_action.button("Deactivate", key="deactivate_api_key_button", help="Deactivate this API key"):
                        with st.spinner(f"Deactivating key {selected_key_info['name']}..."):
                            if security_core.deactivate_api_key(selected_key_id, user_id):
                                st.success(f"API Key '{selected_key_info['name']}' deactivated successfully.")
                                st.rerun()
                            else:
                                st.error(f"Failed to deactivate API Key '{selected_key_info['name']}'.")
                elif selected_key_info['status'] == 'inactive':
                    if col_action.button("Activate", key="activate_api_key_button", type="primary", help="Activate this API key"):
                        with st.spinner(f"Activating key {selected_key_info['name']}..."):
                            if security_core.activate_api_key(selected_key_id, user_id):
                                st.success(f"API Key '{selected_key_info['name']}' activated successfully.")
                                st.rerun()
                            else:
                                st.error(f"Failed to activate API Key '{selected_key_info['name']}'.")
                
                if col_action.button("Delete", key="delete_api_key_button", help="Permanently delete this API key"):
                    if st.warning(f"Are you sure you want to permanently delete API Key '{selected_key_info['name']}'? This cannot be undone."):
                        if st.button("Confirm Delete", key="confirm_delete_api_key", type="secondary"):
                            with st.spinner(f"Deleting key {selected_key_info['name']}..."):
                                if security_core.delete_api_key(selected_key_id, user_id):
                                    st.success(f"API Key '{selected_key_info['name']}' deleted successfully.")
                                    st.rerun()
                                else:
                                    st.error(f"Failed to delete API Key '{selected_key_info['name']}'.")
            else:
                st.warning("Please select an API key to manage.")
    else:
        st.info("You don't have any API keys yet.")

    # Add new API key form
    st.markdown("---")
    st.subheader("Generate New API Key")
    with st.form("new_api_key_form"):
        key_name = st.text_input("Key Name", help="A descriptive name for your API key (e.g., 'My Dashboard Integration')", max_chars=255)
        service = st.text_input("Service", help="Which service will this key be used for (e.g., 'Stripe', 'OpenAI')", max_chars=255)
        permissions = st.selectbox("Permissions", options=list(security_core.API_KEY_PERMISSIONS), help="Permissions level for this key.", index=0)
        
        submitted = st.form_submit_button("Generate Key", type="primary")

        if submitted:
            if not key_name or not service:
                st.error("Key Name and Service are required.")
            else:
                # Generate a secure random key. This is the actual API key value.
                new_api_key_value = secrets.token_urlsafe(32) 
                
                with st.spinner("Generating new API key..."):
                    generated_key_id = security_core.add_api_key(
                        user_id, key_name, new_api_key_value, service, permissions
                    )
                    if generated_key_id:
                        st.success("API Key generated and stored securely!")
                        st.markdown(f"**New API Key ID:** `{generated_key_id}`")
                        st.markdown(f"**Your new API Key (copy now, it won't be shown again!):**")
                        st.code(new_api_key_value, language="plaintext")
                        st.warning("Please copy the API key above now. For security reasons, we do not store this plain-text key and cannot show it again.")
                        st.rerun() # Rerun to update the list of keys
                    else:
                        st.error("Failed to generate API Key. Please check logs for details.")

# --- Password Reset Functions (New) ---
def forgot_password_page(security_core_instance: SecurityCore, email_automation_instance: EmailAutomation):
    st.title("Forgot Your Password?")
    st.write("Enter your email address to receive a password reset link.")

    email = st.text_input("Email Address", key="forgot_email_input")

    if st.button("Send Reset Link", key="send_reset_link_button", type="primary"):
        if email:
            with st.spinner("Sending password reset link..."):
                try:
                    # In SecurityCore, generate_password_reset_token should handle user lookup and token storage
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
                        # For security, avoid revealing if email exists or not. Give a generic message.
                        st.success("If an account with that email exists, a password reset link has been sent.")
                        st.toast("Attempted to send link!", icon="✅")
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
                # Validate password strength using the SecurityCore method
                is_strong, strength_message = security_core_instance.validate_password_strength(new_password)
                if not is_strong:
                    st.error(strength_message)
                else:
                    with st.spinner("Resetting your password..."):
                        try:
                            # In SecurityCore, reset_user_password should hash the password and update DB
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
                    user_
