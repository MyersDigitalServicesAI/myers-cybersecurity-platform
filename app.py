import os
import streamlit as st
from dotenv import load_dotenv
from security_core_pg import SecurityCore
from setup_wizard import SetupWizard

# Load environment variables
load_dotenv()

# Check for required environment variables
required_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'DATABASE_URL', 'STRIPE_SECRET_KEY']
missing_vars = [var for var in required_vars if not os.environ.get(var)]
if missing_vars:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize core modules
security_core = SecurityCore()

# App title/branding
st.set_page_config(page_title="Myers Cybersecurity", page_icon="🛡️", layout="wide")
st.markdown("<h1 style='text-align: center;'>🛡️ Myers Cybersecurity Platform</h1>", unsafe_allow_html=True)

# Session state setup
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'home'

def show_login():
    st.markdown("## Login")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", type="primary")
        if submitted:
            user = security_core.authenticate_user(email, password)
            if user and user['status'] == 'active':
                st.session_state.authenticated = True
                st.session_state.user_id = user['id']
                st.session_state.user_email = email
                st.session_state.user_role = user['role']
                st.session_state.current_page = 'dashboard'
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid credentials or inactive account.")

def show_dashboard():
    st.markdown("## Dashboard")
    st.write("Welcome to your Myers Cybersecurity dashboard!")
    st.write("Select features from the sidebar.")
    st.info("This is your main dashboard. Implement analytics, user management, reporting, etc. here.")

    # Example: Show basic user info if available
    if 'user_id' in st.session_state:
        details = security_core.get_user_details(st.session_state.user_id)
        if details:
            st.write("### Your Account")
            st.json(details)
    
    # Logout
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("Logged out.")
        st.rerun()

def show_home():
    st.markdown("### Welcome to Myers Cybersecurity")
    st.write("Enterprise security, compliance, and API management made easy.")
    st.button("Get Started", on_click=lambda: set_setup_state())

def set_setup_state():
    st.session_state.current_page = 'setup'
    st.session_state.setup_step = 0

def main():
    # Sidebar navigation
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=80)
        st.markdown("## Myers Cybersecurity")
        if st.session_state.get('authenticated'):
            st.markdown(f"User: **{st.session_state.get('user_email', '')}**")
            st.markdown(f"Role: **{st.session_state.get('user_role', '')}**")
            if st.button("Dashboard"):
                st.session_state.current_page = 'dashboard'
            if st.button("Logout"):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
        else:
            if st.button("Login"):
                st.session_state.current_page = 'login'
            if st.button("Setup Wizard"):
                set_setup_state()

    # Main page content routing
    if st.session_state.current_page == 'dashboard' and st.session_state.get('authenticated'):
        show_dashboard()
    elif st.session_state.current_page == 'login':
        show_login()
    elif st.session_state.current_page == 'setup':
        SetupWizard(security_core).show_setup_wizard()
    else:
        show_home()

if __name__ == "__main__":
    main()
