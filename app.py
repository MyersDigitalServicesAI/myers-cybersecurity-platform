import streamlit as st
import os
import secrets
import logging
import pandas as pd
from datetime import datetime
from ratelimit import limits, sleep_and_retry
import time
import requests

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Validate Required Environment Variables ---
required_env_vars = [
    'DATABASE_URL', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET',
    'SENDER_EMAIL', 'SMTP_SERVER', 'SMTP_PORT', 'SMTP_USER', 'SMTP_API_KEY',
    'APP_URL', 'SETUP_ADMIN_EMAIL', 'JWT_SECRET_KEY', 'FERNET_KEY', 'CAPTCHA_SECRET_KEY',
    'RATE_LIMIT_CALLS', 'RATE_LIMIT_PERIOD'
]

missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    logger.critical(f"Missing required environment variables: {', '.join(missing_vars)}")
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

# --- Import modules ---
from security_core import SecurityCore
from payment import PaymentProcessor
from billing import BillingManager
from email_automation import EmailAutomation, EmailEventHandler
from setup_wizard import SetupWizard
from signup_and_email_verification import show_signup_page, show_email_verification_page, show_awaiting_verification_page
from threat_detection_dashboard import show_threat_detection_dashboard
from admin_panel_module import show_admin_panel

# --- Streamlit Caching for Services ---
@st.cache_resource(ttl=None)
def get_security_core_instance():
    return SecurityCore()

@st.cache_resource(ttl=None)
def get_payment_processor_instance():
    return PaymentProcessor()

@st.cache_resource(ttl=None)
def get_email_automation_instance():
    return EmailAutomation()

# --- Token and Encryption Configuration ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
FERNET_KEY = os.getenv("FERNET_KEY")
CAPTCHA_SECRET_KEY = os.getenv("CAPTCHA_SECRET_KEY")
RATE_LIMIT_CALLS = int(os.getenv("RATE_LIMIT_CALLS"))
RATE_LIMIT_PERIOD = int(os.getenv("RATE_LIMIT_PERIOD"))

# --- CAPTCHA Verification Helper ---
def verify_captcha(response_token):
    try:
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                'secret': CAPTCHA_SECRET_KEY,
                'response': response_token
            }
        )
        result = resp.json()
        ip_address = requests.get("https://api64.ipify.org?format=json").json().get("ip", "unknown")
        if not result.get("success"):
            logger.warning(f"CAPTCHA failed for IP {ip_address}. Full response: {result}")
        return resp.status_code == 200 and result.get("success")
    except Exception as e:
        logger.error(f"CAPTCHA verification failed: {e}", exc_info=True)
        return False

# --- Rate Limiting Decorator ---
@sleep_and_retry
@limits(calls=RATE_LIMIT_CALLS, period=RATE_LIMIT_PERIOD)
def rate_limited_action():
    return True

# --- Logging Redaction Wrapper ---
def log_safe(message):
    for secret_key in ["JWT_SECRET_KEY", "FERNET_KEY", "SMTP_API_KEY", "STRIPE_SECRET_KEY"]:
        value = os.getenv(secret_key, "[REDACTED]")
        if value:
            message = message.replace(value, "***")
    logger.info(message)

# --- Page Routing & Session Management ---
def init_session():
    defaults = {
        'authenticated': False,
        'current_page': 'login',
        'user_email': '',
        'user_id': None,
        'first_name': '',
        'last_name': '',
        'company_name': '',
        'user_role': 'user',
        'selected_plan': '',
        'security_core': get_security_core_instance(),
        'email_automation': get_email_automation_instance(),
        'payment_processor': get_payment_processor_instance()
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# --- Login Page ---
def show_login_page():
    st.title("Login to Myers Cybersecurity")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        captcha_response = st.text_input("CAPTCHA Token (simulated)")
        submitted = st.form_submit_button("Login")

        if submitted:
            if not verify_captcha(captcha_response):
                st.error("CAPTCHA failed. Please try again.")
                return
            try:
                rate_limited_action()
                user_data, error = st.session_state.security_core.authenticate_user(email, password)
                if user_data:
                    st.session_state.update({
                        'authenticated': True,
                        'current_page': 'dashboard',
                        'user_email': email,
                        'user_id': user_data['user_id'],
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'company_name': user_data['company'],
                        'user_role': user_data['role'],
                        'selected_plan': user_data.get('plan', 'basic')
                    })
                    st.success("Login successful!")
                    st.experimental_rerun()
                else:
                    st.error(f"Login failed: {error}")
            except Exception as e:
                log_safe(f"Login exception: {e}")
                st.error("Unexpected error during login.")

# --- Logout Helper ---
def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.experimental_rerun()

# --- Render Page Based on State ---
def render_main():
    init_session()
    if not st.session_state.authenticated:
        show_login_page()
    else:
        pages = {
            'dashboard': show_threat_detection_dashboard,
            'subscription': lambda: st.write("Subscription Page Placeholder"),
            'admin': show_admin_panel,
            'logout': logout
        }
        st.sidebar.title("Navigation")
        choice = st.sidebar.radio("Go to", list(pages.keys()), index=0)
        st.session_state.current_page = choice
        pages[choice]()

# --- Start App ---
if __name__ == "__main__":
    render_main()
