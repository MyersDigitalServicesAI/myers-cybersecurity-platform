import streamlit as st
import streamlit_antd_components as sac
import requests
import os

# --- Module-level logger setup ---
import logging
logger = logging.getLogger(__name__)

# --- Configuration ---
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")

def show_settings_page():
    """
    Renders a professional, branded settings page for users to manage
    their profile, change their password, and access billing.
    This version is fully functional and connected to the backend API.
    """
    st.title("⚙️ Account Settings")
    st.text("Manage your profile, password, and subscription.")

    # --- API Call Helper ---
    def get_api_headers():
        return {"Authorization": f"Bearer {st.session_state.jwt}"}

    # --- UI Tabs for Organization ---
    selected_tab = sac.tabs([
        sac.TabsItem(label='Profile', icon='person-fill'),
        sac.TabsItem(label='Change Password', icon='lock-fill'),
        sac.TabsItem(label='Billing', icon='credit-card-fill'),
    ], format_func='title', align='center')

    # --- Profile Settings Tab ---
    if selected_tab == 'Profile':
        st.subheader("Update Your Profile")
        with st.form("update_profile_form"):
            first_name = st.text_input("First Name", value=st.session_state.get('first_name', ''))
            last_name = st.text_input("Last Name", value=st.session_state.get('last_name', ''))
            
            submitted = st.form_submit_button("Save Changes", type="primary")
            if submitted:
                with st.spinner("Saving changes..."):
                    try:
                        payload = {"first_name": first_name, "last_name": last_name}
                        response = requests.put(f"{API_BASE_URL}/users/me", headers=get_api_headers(), json=payload)
                        if response.status_code == 200:
                            # Update session state with new name
                            st.session_state.first_name = first_name
                            st.session_state.last_name = last_name
                            sac.alert(message="Success", description="Profile updated successfully.", type='success')
                        else:
                            sac.alert(message="Error", description=f"Failed to update profile: {response.json().get('detail')}", type='error')
                    except requests.exceptions.RequestException as e:
                        sac.alert(message="Connection Error", description=f"Could not connect to the API: {e}", type='error')

    # --- Change Password Tab ---
    elif selected_tab == 'Change Password':
        st.subheader("Change Your Password")
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            submitted = st.form_submit_button("Update Password", type="primary")
            if submitted:
                if not all([current_password, new_password, confirm_password]):
                    sac.alert(message="Error", description="All fields are required.", type='error')
                elif new_password != confirm_password:
                    sac.alert(message="Error", description="New passwords do not match.", type='error')
                else:
                    with st.spinner("Updating password..."):
                        try:
                            payload = {"current_password": current_password, "new_password": new_password}
                            response = requests.post(f"{API_BASE_URL}/users/me/change-password", headers=get_api_headers(), json=payload)
                            if response.status_code == 200:
                                sac.alert(message="Success", description="Password updated successfully.", type='success')
                            else:
                                sac.alert(message="Error", description=f"Failed to update password: {response.json().get('detail')}", type='error')
                        except requests.exceptions.RequestException as e:
                            sac.alert(message="Connection Error", description=f"Could not connect to the API: {e}", type='error')

    # --- Billing Tab ---
    elif selected_tab == 'Billing':
        st.subheader("Manage Your Subscription")
        st.info(f"You are currently on the **{st.session_state.get('plan', 'Pro')} Plan**.")
        st.write("Click the button below to be securely redirected to our payment provider to manage your subscription, view invoices, or update your payment method.")
        
        if st.button("Manage Billing in Stripe Portal", type="primary", use_container_width=True):
            with st.spinner("Redirecting to billing portal..."):
                try:
                    response = requests.post(
                        f"{API_BASE_URL}/billing/create-portal-session",
                        headers=get_api_headers()
                    )
                    if response.status_code == 200:
                        portal_url = response.json().get("portal_url")
                        # Use st.markdown to create a clickable link
                        st.markdown(f'<meta http-equiv="refresh" content="0; url={portal_url}">', unsafe_allow_html=True)
                        st.success("Redirecting...")
                    else:
                        error_detail = response.json().get("detail", "Could not create billing session.")
                        sac.alert(message="Error", description=error_detail, type='error')
                except requests.exceptions.RequestException as e:
                    sac.alert(message="Connection Error", description=f"Could not connect to the billing service: {e}", type='error')
