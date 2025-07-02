import streamlit as st
import os
import logging

# Assuming these imports are correct based on your project structure
from security_core import SecurityCore
from setup_wizard import SetupWizard
# Import database utility functions
from utils.database import init_db_pool, close_db_pool, get_db_connection, return_db_connection

# Assuming other module imports for pages
# from signup_module import SignUpModule # If you implement this
# from admin_panel_module import AdminPanelModule # If you implement this
from threat_dashboard import show_threat_detection_dashboard # Assuming this is a function

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Streamlit Page Navigation (simplified) ---
def set_page(page_name):
    st.session_state.current_page = page_name

def render_page():
    if st.session_state.current_page == 'setup':
        setup_wizard = st.session_state.setup_wizard
        setup_wizard.show_setup_wizard()
    elif st.session_state.current_page == 'login':
        show_login_page()
    elif st.session_state.current_page == 'dashboard':
        show_dashboard_page()
    elif st.session_state.current_page == 'admin_panel':
        show_admin_panel_page() # Placeholder
    elif st.session_state.current_page == 'signup':
        show_signup_page() # Placeholder
    elif st.session_state.current_page == 'threat_dashboard':
        show_threat_detection_dashboard(st.session_state.security_core)
    else:
        st.session_state.current_page = 'login' # Default to login
        st.rerun()

# --- Placeholder Pages (implement these fully) ---
def show_login_page():
    st.title("Login to Myers Cybersecurity")
    # Your login form and logic here
    st.write("Login form goes here.")
    username = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        # Example: Authenticate user
        user = st.session_state.security_core.get_user_by_email(username)
        if user and st.session_state.security_core.check_password(password, user['password_hash']):
            st.session_state.authenticated = True
            st.session_state.user_id = str(user['id'])
            st.session_state.user_email = user['email']
            st.session_state.user_role = user['role']
            st.session_state.first_name = user['first_name']
            st.session_state.last_name = user['last_name']
            st.session_state.company_name = user['company_name']
            st.session_state.selected_plan = user['plan']
            st.session_state.security_core.update_user_last_login(user['id'])
            st.success(f"Welcome, {user['first_name']}!")
            set_page('dashboard')
            st.rerun()
        else:
            st.error("Invalid email or password.")
    
    st.markdown("---")
    st.write("Don't have an account?")
    if st.button("Sign Up"):
        set_page('signup')
        st.rerun()

def show_signup_page():
    st.title("Sign Up for Myers Cybersecurity")
    # Your signup form and logic here
    st.write("Signup form goes here.")
    # This should ideally use the signup_module.py if you decide to populate it
    if st.button("Back to Login"):
        set_page('login')
        st.rerun()

def show_dashboard_page():
    st.title(f"Welcome, {st.session_state.first_name}!")
    st.subheader("Your Cybersecurity Dashboard")
    
    st.write(f"Company: {st.session_state.company_name}")
    st.write(f"Current Plan: {st.session_state.selected_plan.title()}")
    st.write(f"User Role: {st.session_state.user_role.title()}")

    st.markdown("---")
    st.subheader("Quick Actions")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("View Threat Dashboard"):
            set_page('threat_dashboard')
            st.rerun()
    with col2:
        if st.session_state.user_role == 'admin':
            if st.button("Admin Panel"):
                set_page('admin_panel')
                st.rerun()
    with col3:
        if st.button("Logout"):
            logout()
            st.rerun()

    st.markdown("---")
    # Example of integrating the threat dashboard
    # You might want to pass security_core instance
    # show_threat_detection_dashboard(st.session_state.security_core) # This is now called via render_page() if current_page is 'threat_dashboard'


def show_admin_panel_page():
    st.title("Admin Panel")
    st.write("Admin functionalities will be displayed here.")
    if st.button("Back to Dashboard"):
        set_page('dashboard')
        st.rerun()

def logout():
    st.session_state.authenticated = False
    st.session_state.pop('user_id', None)
    st.session_state.pop('user_email', None)
    st.session_state.pop('user_role', None)
    st.session_state.pop('first_name', None)
    st.session_state.pop('last_name', None)
    st.session_state.pop('company_name', None)
    st.session_state.pop('selected_plan', None)
    st.success("You have been logged out.")
    set_page('login')


def initialize_services():
    """Initializes core services and sets up session state."""
    if 'initialized' not in st.session_state:
        st.session_state.initialized = False

    if not st.session_state.initialized:
        st.info("Initializing application services...")
        try:
            # Initialize the database connection pool FIRST
            # This must be called before any SecurityCore or other database-dependent operations
            init_db_pool()
            logger.info("Database connection pool initialized successfully.")

            st.session_state.security_core = SecurityCore()
            # Now, call init_database() on the security_core instance to create tables
            st.session_state.security_core.init_database() # THIS IS THE CRUCIAL ADDITION
            logger.info("SecurityCore database tables ensured.")

            st.session_state.setup_wizard = SetupWizard(st.session_state.security_core)
            
            # Check if initial setup is required
            # A simple check: if no admin user exists, prompt for setup
            admin_users = st.session_state.security_core.get_all_users_by_role('admin')
            if not admin_users:
                st.session_state.current_page = 'setup'
            else:
                st.session_state.current_page = 'login'

            st.session_state.authenticated = False # User is not authenticated by default
            st.session_state.initialized = True
            logger.info("Application services initialized.")
            st.rerun() # Rerun to display the correct initial page
        except Exception as e:
            logger.critical(f"Failed to initialize application services: {e}", exc_info=True)
            st.error(f"Application failed to start: {e}. Please check server logs and environment variables (DATABASE_URL, JWT_SECRET_KEY, ENCRYPTION_KEY).")
            # Prevent further execution if critical services fail
            st.stop()


def main():
    st.set_page_config(layout="wide", page_title="Myers Cybersecurity Platform")

    # Initialize session state variables if they don't exist
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'loading' # A temporary state while services initialize

    # Call initialization function
    if st.session_state.current_page == 'loading':
        initialize_services()
    else:
        # Render the current page based on session state
        render_page()

if __name__ == '__main__':
    main()
