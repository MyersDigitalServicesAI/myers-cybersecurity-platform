import streamlit as st
import streamlit_antd_components as sac
import requests
import os

# --- Module-level logger setup ---
import logging
logger = logging.getLogger(__name__)

# --- Configuration ---
# Fetch the API base URL from environment variables for flexibility
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")

def show_login_form():
    """
    Renders a professional login form and handles the authentication logic
    by calling the FastAPI backend.
    """
    st.image("https://i.imgur.com/h233fm5.png", width=100) # Placeholder for MyersDigital logo
    st.title("Welcome Back")
    st.text("Enter your credentials to access your dashboard.")
    
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        
        submitted = st.form_submit_button("Login", type="primary", use_container_width=True)
        if submitted:
            if not email or not password:
                sac.alert(message="Error", description="Email and password are required.", type='error', banner=True)
                return

            try:
                # --- API Call to /token endpoint ---
                response = requests.post(
                    f"{API_BASE_URL}/token",
                    data={"username": email, "password": password} # FastAPI's OAuth2 expects form data
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    st.session_state.authenticated = True
                    st.session_state.jwt = token_data['access_token']
                    # Fetch user details to populate session state
                    headers = {"Authorization": f"Bearer {st.session_state.jwt}"}
                    user_res = requests.get(f"{API_BASE_URL}/users/me", headers=headers)
                    if user_res.status_code == 200:
                        user_data = user_res.json()
                        st.session_state.user_id = user_data['id']
                        st.session_state.user_email = user_data['email']
                        st.session_state.user_role = user_data['role']
                        st.session_state.first_name = user_data['first_name']
                    
                    sac.alert(message="Login Successful", description="Redirecting to your dashboard...", type='success', banner=True)
                    st.session_state.current_page = 'dashboard'
                    st.rerun()

                else:
                    error_detail = response.json().get("detail", "An unknown error occurred.")
                    sac.alert(message="Login Failed", description=error_detail, type='error', banner=True)

            except requests.exceptions.RequestException as e:
                logger.error(f"API connection error during login: {e}")
                sac.alert(message="Connection Error", description="Could not connect to the authentication service. Please try again later.", type='error', banner=True)

def show_signup_form():
    """
    Renders a professional signup form and handles new user registration
    by calling the FastAPI backend.
    """
    st.image("https://i.imgur.com/h233fm5.png", width=100) # Placeholder for MyersDigital logo
    st.title("Create Your Account")
    st.text("Join the Myers Cybersecurity Platform.")

    with st.form("signup_form"):
        first_name = st.text_input("First Name")
        last_name = st.text_input("Last Name")
        company_name = st.text_input("Company Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")

        submitted = st.form_submit_button("Create Account", type="primary", use_container_width=True)
        if submitted:
            # --- Form Validation ---
            if not all([first_name, last_name, company_name, email, password]):
                sac.alert(message="Error", description="All fields are required.", type='error', banner=True)
                return

            # --- API Call to /signup endpoint ---
            signup_payload = {
                "email": email,
                "password": password,
                "company_name": company_name,
                "first_name": first_name,
                "last_name": last_name
            }
            try:
                response = requests.post(f"{API_BASE_URL}/signup", json=signup_payload)
                
                if response.status_code == 201: # 201 Created
                    sac.alert(message="Signup Successful!", description="Please check your email to verify your account before logging in.", type='success', banner=True)
                else:
                    error_detail = response.json().get("detail", "An unknown error occurred during signup.")
                    sac.alert(message="Signup Failed", description=error_detail, type='error', banner=True)
            
            except requests.exceptions.RequestException as e:
                logger.error(f"API connection error during signup: {e}")
                sac.alert(message="Connection Error", description="Could not connect to the registration service. Please try again later.", type='error', banner=True)

