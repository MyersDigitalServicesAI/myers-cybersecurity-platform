import streamlit as st
import os
import logging
from datetime import datetime

# --- Hardened Module Imports ---
# These imports assume the corrected, production-ready versions of each module are in place.
from security_core import SecurityCore
from setup_wizard import SetupWizard
from utils.database import init_db_pool, close_db_pool # Assuming this is now in the project structure
# from threat_dashboard import show_threat_detection_dashboard # Assuming this file exists

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ======================================================================================
# --- 1. APPLICATION INITIALIZATION & STATE MACHINE ---
# ======================================================================================

def initialize_app():
    """
    A robust, state-driven function to initialize the application.
    This fixes the "Flawed Initialization" finding by creating a clear, resilient startup sequence.
    """
    if 'app_state' not in st.session_state:
        st.session_state.app_state = 'initializing'
        st.session_state.current_page = 'login' # Default page after initialization
        st.session_state.authenticated = False

    if st.session_state.app_state == 'initializing':
        with st.spinner("Initializing application services..."):
            try:
                # Initialize the database pool first
                init_db_pool()
                
                # Initialize the core security module
                st.session_state.security_core = SecurityCore()
                
                # Check if the database schema needs to be created
                st.session_state.security_core.init_database()
                
                # Check if an admin user exists. If not, the app needs setup.
                # This is a more efficient check than getting all users.
                if not st.session_state.security_core.get_user_by_email(os.environ.get("ADMIN_EMAIL", "admin@example.com")):
                     st.session_state.app_state = 'needs_setup'
                else:
                     st.session_state.app_state = 'ready'
                
                logger.info(f"Application state transitioned to: {st.session_state.app_state}")
                st.rerun()

            except Exception as e:
                logger.critical(f"FATAL: Failed to initialize application services: {e}", exc_info=True)
                st.session_state.app_state = 'error'
                st.session_state.error_message = str(e)
                st.rerun()

# ======================================================================================
# --- 2. PAGE COMPONENTS & UI LOGIC ---
# ======================================================================================

def show_login_page():
    """
    Displays the login page and handles user authentication.
    This fixes the "Incorrect SecurityCore Method Calls" finding.
    """
    st.title("Myers Cybersecurity Platform")
    st.subheader("Admin Login")

    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if not email or not password:
                st.error("Email and password are required.")
                return

            security_core = st.session_state.security_core
            user = security_core.get_user_by_email(email)

            if user and security_core.check_password(password, user['password_hash']):
                # --- FIX APPLIED: Use the consolidated update_user method ---
                security_core.update_user(user['id'], {'last_login': datetime.utcnow()})

                # Populate session state upon successful login
                st.session_state.authenticated = True
                st.session_state.user_id = str(user['id'])
                st.session_state.user_email = user['email']
                st.session_state.user_role = user['role']
                st.session_state.first_name = user['first_name']
                
                st.success(f"Welcome, {st.session_state.first_name}!")
                st.session_state.current_page = 'dashboard'
                st.rerun()
            else:
                st.error("Invalid email or password.")

def show_setup_page():
    """
    Displays the initial setup wizard if no admin user is found.
    """
    st.title("Welcome to Myers Cybersecurity Platform Setup")
    st.info("No admin user found. Please complete the initial setup.")
    
    # Initialize the setup wizard if it doesn't exist
    if 'setup_wizard' not in st.session_state:
        st.session_state.setup_wizard = SetupWizard(st.session_state.security_core)
        
    st.session_state.setup_wizard.show_setup_wizard()
    
    # After setup is complete, the wizard should set the app_state to 'ready'
    # and rerun, which will then direct to the login page.

def show_dashboard_page():
    """
    Displays the main application dashboard for authenticated users.
    """
    st.sidebar.title("Navigation")
    st.sidebar.write(f"Welcome, {st.session_state.get('first_name', 'User')}!")
    
    if st.sidebar.button("Dashboard", use_container_width=True):
        st.session_state.current_page = 'dashboard'
        st.rerun()
    if st.sidebar.button("API Keys", use_container_width=True):
        st.session_state.current_page = 'api_keys'
        st.rerun()
    if st.sidebar.button("Settings", use_container_width=True):
        st.session_state.current_page = 'settings'
        st.rerun()
    if st.sidebar.button("Logout", use_container_width=True):
        logout() # This will rerun automatically

    # --- Main Page Content ---
    st.title("Cybersecurity Dashboard")
    st.write("This is the main dashboard area. Key metrics and alerts will be displayed here.")
    # Placeholder for actual dashboard content
    st.info("Dashboard content is under construction.")


def logout():
    """Clears the session state to log the user out."""
    keys_to_clear = [
        'authenticated', 'user_id', 'user_email', 'user_role', 'first_name'
    ]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    
    st.session_state.authenticated = False
    st.session_state.current_page = 'login'
    st.rerun()

# ======================================================================================
# --- 3. MAIN APPLICATION ROUTER ---
# ======================================================================================

def main():
    """
    The main function that sets up the page and routes the user based on state.
    """
    st.set_page_config(layout="wide", page_title="Myers Cybersecurity")

    # --- State-driven execution flow ---
    if st.session_state.get('app_state') == 'initializing':
        initialize_app()
        st.info("Initializing...") # Show a message while initializing

    elif st.session_state.get('app_state') == 'needs_setup':
        show_setup_page()

    elif st.session_state.get('app_state') == 'ready':
        if st.session_state.get('authenticated'):
            # User is logged in, show the appropriate page
            page = st.session_state.get('current_page', 'dashboard')
            if page == 'dashboard':
                show_dashboard_page()
            # Add other authenticated pages here (e.g., api_keys, settings)
            else:
                show_dashboard_page() # Default to dashboard
        else:
            # User is not logged in, show the login page
            show_login_page()

    elif st.session_state.get('app_state') == 'error':
        st.error("A critical error occurred during application startup.")
        st.exception(st.session_state.get('error_message', 'Unknown error.'))

    else:
        # Fallback to re-initialize if state is unknown
        initialize_app()

if __name__ == '__main__':
    # This block runs when the script is executed directly.
    # It's the entry point of the Streamlit application.
    main()
