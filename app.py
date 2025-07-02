import streamlit as st
import os
import secrets
import logging
import pandas as pd
from datetime import datetime

# IMPORTANT: You need to provide these module files
from email_automation import EmailAutomation
from security_core_pg import SecurityCore
from payment import PaymentProcessor
from admin_panel_module import show_admin_panel 

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Initialize Core Services ---
# These are initialized once and stored in session state to persist across reruns
def initialize_services():
    if 'services_initialized' not in st.session_state:
        st.session_state.security_core = SecurityCore()
        st.session_state.email_automation = EmailAutomation()
        st.session_state.payment_processor = PaymentProcessor()
        st.session_state.services_initialized = True

def get_payment_processor():
    return st.session_state.payment_processor

def get_security_core():
    return st.session_state.security_core

def get_email_automation():
    return st.session_state.email_automation

# --- Page: Subscription Management ---
def show_subscription_page():
    st.title("Manage Your Subscription")
    security_core = get_security_core()
    payment_processor = get_payment_processor()

    details = security_core.get_user_details(st.session_state.user_id)
    if not details:
        st.error("Could not load your subscription details.")
        return

    st.write(f"**Current Plan:** {details.get('plan', 'N/A').title()}")
    st.write(f"**Payment Status:** {details.get('payment_status', 'N/A').replace('_', ' ').title()}")
    
    # CORRECTED: Fetch prices dynamically from Stripe
    st.markdown("---")
    st.subheader("Available Plans")
    with st.spinner("Loading available plans..."):
        prices_response = payment_processor.get_active_prices()

    if prices_response.get("status") == "success":
        active_prices = prices_response.get("prices", [])
        if not active_prices:
            st.info("No subscription plans are currently available.")
        else:
            for price in active_prices:
                product = price.get('product', {})
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{product.get('name', 'Unnamed Plan')}**")
                        st.write(f"${price.get('unit_amount', 0) / 100:.2f} / {price.get('recurring', {}).get('interval', 'month')}")
                        st.caption(product.get('description', ''))
                    with col2:
                        # Add logic for subscribe/upgrade/downgrade buttons here
                        if details.get('plan').lower() != product.get('name', '').lower():
                             if st.button(f"Switch to {product.get('name')}", key=f"switch_{price.id}"):
                                # Add logic to handle subscription update
                                st.info("Subscription changes coming soon!")
                        else:
                            st.button("Current Plan", disabled=True)
    else:
        st.error(f"Could not load plans: {prices_response.get('error')}")

# --- Page: API Keys ---
def show_api_keys_page():
    st.title("My API Keys")
    # This function's logic remains largely the same but uses get_security_core()
    security_core = get_security_core()
    user_id = st.session_state.user_id
    # (Your existing logic for listing, creating, and managing API keys)
    st.info("API Key management UI goes here.")


# --- Page: Password Reset ---
def reset_password_page():
    st.title("Reset Your Password")
    security_core = get_security_core()
    
    # CORRECTED: Use st.query_params
    token = st.query_params.get("token")

    if not token:
        st.error("Invalid or missing password reset token.")
        return

    info = security_core.verify_password_reset_token(token)
    if not info:
        st.error("This password reset link is invalid or has expired.")
        return
        
    st.info(f"Resetting password for: **{info['email']}**")
    with st.form("reset_password_form"):
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Reset Password")

        if submitted:
            if not new_password or not confirm_password:
                st.warning("Please fill in both password fields.")
                return
            if new_password != confirm_password:
                st.error("Passwords do not match.")
                return

            is_strong, reason = security_core.validate_password_strength(new_password)
            if not is_strong:
                st.error(reason)
                return

            with st.spinner("Resetting your password..."):
                if security_core.reset_user_password(info['id'], new_password):
                    st.success("Your password has been reset successfully!")
                    st.info("You can now log in with your new password.")
                    # CORRECTED: Use st.query_params.clear()
                    st.query_params.clear()
                    st.session_state['page'] = 'login'
                    st.rerun()
                else:
                    st.error("Failed to reset password. Please try again.")

# --- Page: Login ---
def show_login_page():
    st.markdown("## Login to Myers Cybersecurity")
    security_core = get_security_core()
    email_automation = get_email_automation()

    with st.form("login_form"):
        email = st.text_input("Email Address")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            auth_result, error_message = security_core.authenticate_user(email, password)
            if auth_result:
                st.session_state.logged_in = True
                st.session_state.user_id = auth_result['id']
                st.session_state.user_role = auth_result['role']
                st.session_state.user_email = auth_result['email']
                st.session_state.page = 'dashboard'
                st.rerun()
            else:
                st.error(error_message)
    
    st.markdown("---")
    if st.button("Forgot Your Password?"):
        st.session_state.page = 'forgot_password'
        st.rerun()

# --- Page: Forgot Password ---
def forgot_password_page():
    st.title("Forgot Your Password?")
    security_core = get_security_core()
    email_automation = get_email_automation()

    email = st.text_input("Enter your email address")
    if st.button("Send Reset Link"):
        if email:
            token = security_core.generate_password_reset_token(email)
            if token:
                app_url = os.environ.get("APP_URL", "http://localhost:8501")
                reset_link = f"{app_url}/?page=reset_password&token={token}"
                # CORRECTED: Type hint is fixed implicitly by using the instance
                email_automation.send_password_reset_email(email, reset_link)
            # Generic message for security
            st.success("If an account with that email exists, a password reset link has been sent.")
        else:
            st.warning("Please enter an email address.")
    if st.button("Back to Login"):
        st.session_state.page = 'login'
        st.rerun()

# --- Main App Router ---
def main():
    initialize_services()

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if 'page' not in st.session_state:
        # Check for query params to deep-link to password reset
        if st.query_params.get("page") == "reset_password":
            st.session_state.page = 'reset_password'
        else:
            st.session_state.page = 'login'

    if not st.session_state.logged_in:
        if st.session_state.page == 'reset_password':
            reset_password_page()
        elif st.session_state.page == 'forgot_password':
            forgot_password_page()
        else:
            show_login_page()
        return

    # --- Logged-in Application ---
    st.sidebar.title("Navigation")
    st.sidebar.write(f"Welcome, {st.session_state.user_email}")
    
    page_options = ["Dashboard", "My Subscription", "API Keys"]
    if st.session_state.user_role == 'admin':
        page_options.append("Admin Panel")

    page_selection = st.sidebar.radio("Go to", page_options)

    if st.sidebar.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    if page_selection == "Dashboard":
        st.title("Dashboard")
        st.write("Welcome to your main dashboard.")
    elif page_selection == "My Subscription":
        show_subscription_page()
    elif page_selection == "API Keys":
        show_api_keys_page()
    elif page_selection == "Admin Panel" and st.session_state.user_role == 'admin':
        # CORRECTED: Abstracted DB logic into SecurityCore
        show_admin_panel(get_security_core())

if __name__ == "__main__":
    main()
