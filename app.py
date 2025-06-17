import os
import logging
import secrets
try:
    import pandas as pd
except ImportError:
    pd = None
try:
    import streamlit as st
except ImportError:
    raise ImportError("The 'streamlit' package is required. Please install it with 'pip install streamlit'.")
logger = logging.getLogger(__name__)
# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Validate Required Environment Variables ---
required_env_vars = [
    'SECRET',
    'DATABASE_URL',
    'STRIPE_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET',
    'SENDER_EMAIL',
    'SMTP_SERVER',
    'SMTP_PORT',
    'SMTP_USER',
    'SMTP_API_KEY',
    'APP_URL',
    'SETUP_ADMIN_EMAIL'
]
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    joined = ', '.join(missing_vars)
    logger.critical(f"Missing required environment variables: {joined}")
    raise EnvironmentError(f"Missing required environment variables: {joined}")

# --- Enhancement: Session Management ---
# Do not log sensitive data (passwords, tokens, API keys, emails in error traces).
# --- Enhancement: Logging ---
# Streamlit does not provide CSRF protection by default. For highly sensitive deployments, consider additional layers (e.g., reverse proxy with CSRF protection).
# --- Enhancement: CSRF protection ---
# Ensure validate_password_strength checks for length, complexity, and common passwords.
# --- Enhancement: Password strength validation ---
# This must be enforced in security_core_pg.py, not here. Review that file for SQL injection risks.
# --- Enhancement: Ensure all database access is parameterized ---

# --- Helper: Check authentication before sensitive pages ---
def require_authentication():
    if not st.session_state.get('authenticated'):
        st.error("You must be logged in to access this page.")
        st.stop()

# --- Dashboard welcome UI ---
def show_dashboard():
    require_authentication()
    st.write(f"Welcome, {st.session_state.get('first_name', '')} {st.session_state.get('last_name', '')} ({st.session_state.get('email', '')})!")
    st.write(f"Your Plan: {st.session_state.get('selected_plan', 'N/A').title()}")
    st.write("This is your main dashboard. More features will appear here based on your subscription.")

# --- Subscription Page ---
def show_subscription_page():
    require_authentication()
    details = st.session_state.security_core.get_details(st.session_state.id)
    st.title("Manage Your Subscription")
    st.write("Details about your current plan, billing, and options to upgrade or manage your subscription.")
    if details:
        trial_ends = details.get('trial_ends')
        st.write(f"**Current Plan:** {details.get('plan', 'N/A').title()} (Trial ends: {trial_ends.strftime('%Y-%m-%d') if trial_ends else 'N/A'})")
        st.write(f"**Payment Status:** {details.get('payment_status', 'N/A').replace('_', ' ').title()}")
        if details.get('is_trial'):
            st.write(f"**Trial Ends:** {trial_ends.strftime('%Y-%m-%d') if trial_ends else 'N/A'}")
        if details.get('subscription_id'):
            st.write(f"**Subscription ID:** {details.get('subscription_id')}")
        st.write(f"**Auto-renewal:** {'Enabled' if details.get('auto_renewal') else 'Disabled'}")
        st.markdown("---")
        st.subheader("Billing Details")
        st.info("Billing information will appear here.")
        plan_prices = {
            'essentials': 50.0,
            'basic': 100.0,
            'professional': 200.0,
            'business': 500.0,
            'enterprise': 1000.0
        }
        plan = details.get('plan')
        billing_period = details.get('billing_period', 'monthly')
        if plan and plan in plan_prices:
            base_price = plan_prices[plan]
            pricing_info = st.session_state.security_core.calculate_discounted_price(
                base_price, plan, billing_period, st.session_state.id
            )
            st.write("#### Your Current Plan Pricing Overview:")
            st.json(pricing_info)
        else:
            st.warning("Could not retrieve detailed pricing for your plan.")
    else:
        st.error("Could not load your subscription details.")

# --- API Keys Page ---
def show_api_keys_page():
    require_authentication()
    st.title("My API Keys")
    st.write("Manage your API keys for integrating with our services.")
    security_core = st.session_state.security_core
    user_id = st.session_state.id
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
        with st.spinner("Loading API keys data..."):
            if pd is not None:
                st.dataframe(pd.DataFrame(keys_data), use_container_width=True)
            else:
                st.write("### API Keys Data")
                for key_data in keys_data:
                    st.write(f"- **{key_data['Name']}** (ID: {key_data['ID']}): {key_data['Service']} - {key_data['Status']}")
    else:
        st.info("You don't have any API keys yet.")

    st.markdown("---")
    col_select, col_action = st.columns([0.7, 0.3])
    st.subheader("Manage Existing Keys")
    if api_keys:
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
                    if st.checkbox(f"Are you sure you want to permanently delete API Key '{selected_key_info['name']}'? This cannot be undone.", key="confirm_delete_api_key"):
                        with st.spinner(f"Deleting key {selected_key_info['name']}..."):
                            if security_core.delete_api_key(selected_key_id, user_id):
                                st.success(f"API Key '{selected_key_info['name']}' deleted successfully.")
                                st.rerun()
                            else:
                                st.error(f"Failed to delete API Key '{selected_key_info['name']}'.")
    else:
        st.error("Could not load your API keys.")

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
                        # Do NOT log or store the plain API key anywhere else!
                    else:
                        st.error("Failed to generate API Key. Please check logs for details.")

# --- Authentication Pages ---
def login_page(security_core_instance: SecurityCore):
    st.title("Login")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_button", type="primary"):
        if email and password:
            with st.spinner("Logging in..."):
                try:
                    auth_result = security_core_instance.authenticate_user(email, password)
                    if auth_result:
                        st.session_state['authenticated'] = True
                        st.session_state['user_id'] = auth_result['id']
                        st.session_state['email'] = auth_result['email']
                        st.session_state['first_name'] = auth_result.get('first_name', '')
                        st.session_state['last_name'] = auth_result.get('last_name', '')
                        st.success("Login successful!")
                        st.experimental_redirect(st.session_state.get('next', '/'))
                    else:
                        st.error("Invalid email or password.")
                except Exception as e:
                    logger.error(f"Error during login: {e}", exc_info=True)
                    st.error("An unexpected error occurred. Please try again later.")
        else:
            st.warning("Please enter both email and password.")

def logout():
    st.session_state.clear()
    st.success("You have been logged out.")
    st.experimental_redirect('/')

def forgot_password_page(security_core_instance: SecurityCore, email_automation_instance: EmailAutomation):
    st.title("Forgot Your Password?")
    st.write("Enter your email address to receive a password reset link.")
    email = st.text_input("Email Address", key="forgot_email_input")
    if st.button("Send Reset Link", key="send_reset_link_button", type="primary"):
        if email:
            with st.spinner("Sending password reset link..."):
                try:
                    token = security_core_instance.generate_password_reset_token(email)
                    reset_link = f"{app_base_url}/?page=reset_password&token={token}"
                    email_sent = email_automation_instance.send_password_reset_email(email, reset_link)
                    st.success("If an account with that email exists, a password reset link has been sent.")
                except Exception as e:
                    logger.error(f"Error in forgot_password_page for {email}: {e}", exc_info=True)
                    st.error("An unexpected error occurred. Please try again later.")
        else:
            st.warning("Please enter your email address.")

def reset_password_page(security_core_instance: SecurityCore):
    token = query_params.get("token", [None])[0]
    query_params = st.experimental_get_query_params()
    st.title("Reset Your Password")
    if not token:
        st.error("Invalid or missing password reset token. Please request a new one.")
        return
    info = security_core_instance.verify_password_reset_token(token)
    if not info:
        st.error("Invalid or missing password reset token. Please request a new one.")
        return
    st.info(f"Resetting password for: **{info['email']}**")
    new_password = st.text_input("New Password", type="password", key="new_password_reset_input")
    confirm_password = st.text_input("Confirm New Password", type="password", key="confirm_password_reset_input")
    if st.button("Reset Password", key="reset_password_button", type="primary"):
        if new_password and confirm_password:
            if new_password == confirm_password:
                is_strong, strength_message = security_core_instance.validate_password_strength(new_password)
                if is_strong:
                    try:
                        with st.spinner("Resetting your password..."):
                            security_core_instance.reset_password(info['id'], new_password)
                            st.success("Your password has been reset successfully! You can now log in.")
                            st.session_state['current_page'] = 'login'
                            st.experimental_set_query_params()
                    except Exception as e:
                        logger.error(f"Error resetting password for user {info['id']}: {e}", exc_info=True)
                        st.error("An unexpected error occurred during password reset. Please try again later.")
            else:
                st.error("Passwords do not match.")
        else:
            st.warning("Please enter both new password and confirmation.")
