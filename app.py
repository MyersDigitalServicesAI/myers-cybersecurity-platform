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
        st.session_
