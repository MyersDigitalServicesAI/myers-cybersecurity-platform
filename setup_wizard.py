import streamlit as st
import os
import logging
from datetime import datetime

# --- Hardened Module Imports ---
from security_core import SecurityCore
from payment import PaymentProcessor

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

class SetupWizard:
    """
    Manages the multi-step process for the initial application setup by the first admin user.
    This class is instantiated once and stored in the Streamlit session state.
    """
    def __init__(self, security_core: SecurityCore):
        self.security_core = security_core
        self.payment_processor = PaymentProcessor()
        self.steps = [
            "Admin Account",
            "Company Information",
            "Final Review"
        ]
        # Initialize session state for the wizard
        if 'setup_step' not in st.session_state:
            st.session_state.setup_step = 0
        if 'setup_data' not in st.session_state:
            st.session_state.setup_data = {}

    def show(self):
        """Renders the current step of the setup wizard."""
        st.title("Myers Cybersecurity Platform Setup")
        
        # Progress indicator
        progress_value = (st.session_state.setup_step) / (len(self.steps) - 1)
        st.progress(progress_value)
        
        current_step_name = self.steps[st.session_state.setup_step]
        st.markdown(f"#### Step {st.session_state.setup_step + 1}: {current_step_name}")

        # --- Step rendering logic ---
        if st.session_state.setup_step == 0:
            self._render_admin_account_step()
        elif st.session_state.setup_step == 1:
            self._render_company_info_step()
        elif st.session_state.setup_step == 2:
            self._render_final_review_step()

    def _render_admin_account_step(self):
        """Step 1: Create the primary admin account."""
        st.subheader("Create Your Administrator Account")
        
        # Use the SETUP_ADMIN_EMAIL from environment as the default, non-editable email
        admin_email = os.environ.get("SETUP_ADMIN_EMAIL", "admin@example.com")
        st.info(f"The primary admin account will be created for: **{admin_email}**")
        st.session_state.setup_data['email'] = admin_email

        with st.form("admin_account_form"):
            st.session_state.setup_data['first_name'] = st.text_input("First Name", value=st.session_state.setup_data.get('first_name', ''))
            st.session_state.setup_data['last_name'] = st.text_input("Last Name", value=st.session_state.setup_data.get('last_name', ''))
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            submitted = st.form_submit_button("Next: Company Information")
            if submitted:
                is_strong, msg = self.security_core.validate_password_strength(password)
                if not all([st.session_state.setup_data['first_name'], password, confirm_password]):
                    st.error("All fields are required.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif not is_strong:
                    st.error(msg)
                else:
                    st.session_state.setup_data['password'] = password
                    st.session_state.setup_step += 1
                    st.rerun()

    def _render_company_info_step(self):
        """Step 2: Collect company information."""
        st.subheader("Tell Us About Your Company")
        with st.form("company_info_form"):
            st.session_state.setup_data['company_name'] = st.text_input("Company Name", value=st.session_state.setup_data.get('company_name', ''))
            
            submitted = st.form_submit_button("Next: Final Review")
            if submitted:
                if not st.session_state.setup_data['company_name']:
                    st.error("Company name is required.")
                else:
                    st.session_state.setup_step += 1
                    st.rerun()

    def _render_final_review_step(self):
        """Step 3: Review all information and complete the setup."""
        st.subheader("Review and Complete Setup")
        data = st.session_state.setup_data

        st.markdown("**Admin Account:**")
        st.write(f"- **Name:** {data.get('first_name')} {data.get('last_name')}")
        st.write(f"- **Email:** {data.get('email')}")
        st.write(f"- **Password:** {'*' * 10}")

        st.markdown("**Company Information:**")
        st.write(f"- **Company Name:** {data.get('company_name')}")
        
        st.markdown("---")
        if st.button("Complete Setup", type="primary"):
            self._execute_setup()

    def _execute_setup(self):
        """
        Executes the final setup process by calling the SecurityCore module.
        This is the rewritten, hardened version of the complete_setup logic.
        """
        with st.spinner("Finalizing setup... This may take a moment."):
            data = st.session_state.setup_data
            
            # --- FIX APPLIED: Use correct SecurityCore method signature ---
            user_id, message = self.security_core.create_user(
                email=data['email'],
                password=data['password'],
                first_name=data['first_name'],
                last_name=data['last_name'],
                company_name=data['company_name'],
                role='admin' # Explicitly set the role to admin
            )

            if not user_id:
                st.error(f"Setup failed during user creation: {message}")
                return

            # --- FIX APPLIED: Use consolidated update_user method ---
            # Mark the admin's email as verified and set the account to active.
            update_payload = {
                'email_verified': True,
                'status': 'active'
            }
            update_success = self.security_core.update_user(user_id, update_payload)

            if not update_success:
                st.error("Setup failed: Could not activate the new admin account.")
                # In a real scenario, you might want to roll back the user creation here.
                return
            
            # --- FIX APPLIED: Use correct API key creation method ---
            # Create a default API key for the new admin.
            api_key, key_message = self.security_core.create_api_key(
                user_id=user_id,
                name="Default Admin Key",
                permissions=["admin"] # Grant full admin permissions
            )

            if not api_key:
                st.warning(f"Admin user was created, but failed to generate an initial API key: {key_message}")
            else:
                st.markdown(f"**Your Initial Admin API Key (save this now, it will not be shown again):**")
                st.code(api_key)

            # --- Finalize and transition app state ---
            st.success("Setup completed successfully! You can now log in.")
            st.balloons()
            
            # Clean up wizard state from session
            del st.session_state['setup_step']
            del st.session_state['setup_data']
            
            # Transition the main app state to 'ready'
            st.session_state.app_state = 'ready'
            st.rerun()
