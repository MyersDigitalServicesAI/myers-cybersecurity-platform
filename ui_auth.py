import streamlit as st
import streamlit_antd_components as sac
import requests
import os
import logging
import re

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

# --- Configuration ---
# Fetch the API base URL from environment variables for flexibility
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")

def inject_custom_css():
    """
    Injects custom CSS for a professional, centered, and branded layout.
    """
    # --- MyersDigital Brand Colors ---
    # Primary Background: A very dark, almost black, navy blue.
    # Card Background: A slightly lighter, muted blue-gray.
    # Primary Text: A light gray/off-white.
    # Accent/Primary Button: A bold, confident blue.
    # Accent Hover: A slightly lighter blue for hover states.
    st.markdown("""
        <style>
            /* --- General Body Styles --- */
            body {
                background-color: #0D1B2A; /* Dark Navy Blue */
            }
            /* --- Main Container for Centering --- */
            .auth-container {
                display: flex;
                justify-content: center;
                align-items: center;
                width: 100%;
                height: 80vh;
            }
            /* --- Branded Auth Card --- */
            .auth-card {
                background-color: #1B263B; /* Muted Blue-Gray */
                padding: 2.5rem;
                border-radius: 15px;
                border: 1px solid #415A77;
                box-shadow: 0 8px 16px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 450px;
                color: #E0E1DD; /* Light Gray/Off-White Text */
            }
            .auth-card h1, .auth-card h2, .auth-card h3 {
                color: #FFFFFF;
            }
            .auth-card .stTextInput label {
                color: #E0E1DD !important;
            }
            .auth-card .stTextInput input {
                background-color: #0D1B2A;
                color: #E0E1DD;
                border: 1px solid #415A77;
            }
            /* --- Branded Buttons --- */
            .auth-card .stButton button {
                background-color: #415A77; /* Accent Blue */
                color: white;
                border-radius: 5px;
                transition: background-color 0.3s ease;
            }
            .auth-card .stButton button:hover {
                background-color: #778DA9; /* Lighter Accent Blue on Hover */
            }
            .auth-card .stButton button[kind="link"] {
                background-color: transparent;
                color: #778DA9;
            }
            .auth-card .stButton button[kind="link"]:hover {
                color: #E0E1DD;
            }
        </style>
    """, unsafe_allow_html=True)

def show_auth_flow():
    """
    Main function to control and render the entire authentication flow (Login, Signup, Forgot Password).
    """
    inject_custom_css()

    if 'auth_page' not in st.session_state:
        st.session_state.auth_page = 'login'

    # Use columns to center the auth card on the page
    _, col2, _ = st.columns([1, 1.5, 1])

    with col2:
        with st.container():
            st.markdown('<div class="auth-card">', unsafe_allow_html=True)
            
            if st.session_state.auth_page == 'login':
                _show_login_form()
            elif st.session_state.auth_page == 'signup':
                _show_signup_form()
            elif st.session_state.auth_page == 'forgot_password':
                _show_forgot_password_form()
                
            st.markdown('</div>', unsafe_allow_html=True)

def _show_login_form():
    """
    Renders a professional login form and handles authentication.
    """
    st.image("https://i.imgur.com/h233fm5.png", width=80) # Placeholder logo
    st.title("Welcome Back")
    st.text("Enter your credentials to access your dashboard.")
    
    with st.form("login_form"):
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)
        if submitted:
            with st.spinner("Authenticating..."):
                if not email or not password:
                    sac.alert(message="Error", description="Email and password are required.", type='error', banner=True)
                    return

                try:
                    response = requests.post(
                        f"{API_BASE_URL}/token",
                        data={"username": email, "password": password}
                    )
                    
                    if response.status_code == 200:
                        token_data = response.json()
                        st.session_state.authenticated = True
                        st.session_state.jwt = token_data['access_token']
                        
                        headers = {"Authorization": f"Bearer {st.session_state.jwt}"}
                        user_res = requests.get(f"{API_BASE_URL}/users/me", headers=headers)
                        if user_res.status_code == 200:
                            user_data = user_res.json()
                            st.session_state.user_id = user_data['id']
                            st.session_state.user_email = user_data['email']
                            st.session_state.user_role = user_data['role']
                            st.session_state.first_name = user_data['first_name']
                        
                        sac.alert(message="Login Successful", description="Redirecting...", type='success', banner=True)
                        st.session_state.current_page = 'dashboard'
                        st.rerun()
                    else:
                        error_detail = response.json().get("detail", "An unknown error occurred.")
                        sac.alert(message="Login Failed", description=error_detail, type='error', banner=True)

                except requests.exceptions.RequestException as e:
                    logger.error(f"API connection error during login: {e}")
                    sac.alert(message="Connection Error", description="Could not connect to the authentication service.", type='error', banner=True)

    sac.divider(label='OR', align='center', dashed=True)
    if st.button("Create New Account", use_container_width=True):
        st.session_state.auth_page = 'signup'
        st.rerun()
    if st.button("Forgot Password?", type='link', use_container_width=True):
        st.session_state.auth_page = 'forgot_password'
        st.rerun()

def _show_signup_form():
    """
    Renders a professional signup form with password confirmation.
    """
    st.image("https://i.imgur.com/h233fm5.png", width=80)
    st.title("Create Your Account")
    st.text("Join the Myers Cybersecurity Platform.")

    with st.form("signup_form"):
        first_name = st.text_input("First Name")
        last_name = st.text_input("Last Name")
        company_name = st.text_input("Company Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        submitted = st.form_submit_button("Create Account", type="primary", use_container_width=True)
        if submitted:
            with st.spinner("Creating account..."):
                if not all([first_name, last_name, company_name, email, password, confirm_password]):
                    sac.alert(message="Error", description="All fields are required.", type='error', banner=True)
                    return
                if password != confirm_password:
                    sac.alert(message="Error", description="Passwords do not match.", type='error', banner=True)
                    return

                signup_payload = {
                    "email": email, "password": password, "company_name": company_name,
                    "first_name": first_name, "last_name": last_name
                }
                try:
                    response = requests.post(f"{API_BASE_URL}/signup", json=signup_payload)
                    if response.status_code == 201:
                        sac.alert(message="Signup Successful!", description="Please check your email to verify your account.", type='success', banner=True)
                        st.session_state.auth_page = 'login' # Switch back to login page
                    else:
                        error_detail = response.json().get("detail", "An unknown error occurred.")
                        sac.alert(message="Signup Failed", description=error_detail, type='error', banner=True)
                
                except requests.exceptions.RequestException as e:
                    logger.error(f"API connection error during signup: {e}")
                    sac.alert(message="Connection Error", description="Could not connect to the registration service.", type='error', banner=True)

    sac.divider(align='center')
    if st.button("Already have an account? Sign In", use_container_width=True):
        st.session_state.auth_page = 'login'
        st.rerun()

def _show_forgot_password_form():
    """
    Renders a form for users to request a password reset link.
    """
    st.image("https://i.imgur.com/h233fm5.png", width=80)
    st.title("Forgot Password")
    st.text("Enter your email to receive a password reset link.")

    with st.form("forgot_password_form"):
        email = st.text_input("Email")
        submitted = st.form_submit_button("Send Reset Link", type="primary", use_container_width=True)
        if submitted:
            with st.spinner("Sending link..."):
                # This is a placeholder. A real implementation would call a `/forgot-password` endpoint.
                if email and re.match(r"[^@]+@[^@]+\.[^@]+", email):
                     sac.alert(message="Request Sent", description=f"If an account exists for {email}, a password reset link has been sent.", type='info', banner=True)
                else:
                     sac.alert(message="Error", description="Please enter a valid email address.", type='error', banner=True)

    sac.divider(align='center')
    if st.button("Back to Login", use_container_width=True):
        st.session_state.auth_page = 'login'
        st.rerun()
