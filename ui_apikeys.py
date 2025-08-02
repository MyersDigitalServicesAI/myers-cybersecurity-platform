import streamlit as st
import streamlit_antd_components as sac
import requests
import os
import pandas as pd
from datetime import datetime

# --- Module-level logger setup ---
import logging
logger = logging.getLogger(__name__)

# --- Configuration ---
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")

def show_api_key_dashboard():
    """
    Renders a professional, branded dashboard for managing API keys.
    It communicates with the secure FastAPI backend to perform all operations.
    """
    st.title("🔑 API Key Management")
    st.text("Create, manage, and revoke your API keys.")
    
    # --- State Management for this page ---
    if 'api_keys' not in st.session_state:
        st.session_state.api_keys = []
    if 'newly_created_key' not in st.session_state:
        st.session_state.newly_created_key = None

    # --- API Call Helper ---
    def get_api_headers():
        return {"Authorization": f"Bearer {st.session_state.jwt}"}

    def fetch_api_keys():
        """Fetches the user's API keys from the backend."""
        try:
            response = requests.get(f"{API_BASE_URL}/api-keys", headers=get_api_headers())
            if response.status_code == 200:
                st.session_state.api_keys = response.json()
            else:
                sac.alert(message="Error", description="Failed to fetch API keys.", type='error')
                st.session_state.api_keys = []
        except requests.exceptions.RequestException as e:
            sac.alert(message="Connection Error", description=f"Could not connect to the API: {e}", type='error')
            st.session_state.api_keys = []

    # --- Initial Data Load ---
    if not st.session_state.api_keys:
        fetch_api_keys()

    # --- Display Newly Created Key (if any) ---
    if st.session_state.newly_created_key:
        sac.alert(
            message="API Key Created Successfully!",
            description="Please copy your new API key now. You will not be able to see it again.",
            type='success',
            banner=True
        )
        st.code(st.session_state.newly_created_key, language=None)
        st.session_state.newly_created_key = None # Clear after displaying

    # --- Create New API Key Form ---
    with st.expander("➕ Create New API Key", expanded=False):
        with st.form("create_api_key_form"):
            key_name = st.text_input("Key Name / Label", placeholder="e.g., My Production Server")
            # In a more advanced version, you could select permissions here
            submitted = st.form_submit_button("Create Key", type="primary")
            if submitted:
                if not key_name:
                    sac.alert(message="Error", description="Key Name is required.", type='error')
                else:
                    with st.spinner("Creating key..."):
                        try:
                            response = requests.post(
                                f"{API_BASE_URL}/api-keys",
                                headers=get_api_headers(),
                                json={"name": key_name, "permissions": ["read", "write"]}
                            )
                            if response.status_code == 201: # 201 Created
                                new_key_data = response.json()
                                st.session_state.newly_created_key = new_key_data.get("raw_key")
                                fetch_api_keys() # Refresh the list
                                st.rerun()
                            else:
                                sac.alert(message="Error", description=f"Failed to create key: {response.json().get('detail')}", type='error')
                        except requests.exceptions.RequestException as e:
                            sac.alert(message="Connection Error", description=f"Could not connect to the API: {e}", type='error')

    st.markdown("---")
    st.subheader("Your Existing API Keys")

    # --- Display API Keys in a Table ---
    if not st.session_state.api_keys:
        st.info("You have not created any API keys yet.")
    else:
        # Prepare data for display
        display_data = []
        for key in st.session_state.api_keys:
            display_data.append({
                "Name": key['name'],
                "Prefix": key['key_prefix'],
                "Created": datetime.fromisoformat(key['created_at']).strftime('%Y-%m-%d %H:%M'),
                "Last Used": datetime.fromisoformat(key['last_used']).strftime('%Y-%m-%d %H:%M') if key['last_used'] else "Never",
                "Expires": datetime.fromisoformat(key['expires_at']).strftime('%Y-%m-%d') if key['expires_at'] else "Never",
                "ID": key['id']
            })
        
        df = pd.DataFrame(display_data)
        st.dataframe(df[['Name', 'Prefix', 'Created', 'Last Used', 'Expires']], use_container_width=True)

        # --- Revoke Key Section ---
        st.markdown("##### Revoke an API Key")
        key_id_to_revoke = st.selectbox("Select a key to revoke", options=[key['ID'] for key in display_data], format_func=lambda x: next((item['Name'] for item in display_data if item['ID'] == x), None))
        
        if st.button("Revoke Selected Key", type="primary", key="revoke_button"):
            with st.spinner("Revoking key..."):
                try:
                    response = requests.delete(f"{API_BASE_URL}/api-keys/{key_id_to_revoke}", headers=get_api_headers())
                    if response.status_code == 200:
                        sac.alert(message="Success", description="API Key has been revoked.", type='success')
                        fetch_api_keys() # Refresh list
                        st.rerun()
                    else:
                        sac.alert(message="Error", description=f"Failed to revoke key: {response.json().get('detail')}", type='error')
                except requests.exceptions.RequestException as e:
                    sac.alert(message="Connection Error", description=f"Could not connect to the API: {e}", type='error')

