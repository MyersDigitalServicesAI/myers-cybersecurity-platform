import pandas as pd
import streamlit as st
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def show_admin_panel(security_core):
    """
    Renders the admin panel for user management and system monitoring.
    """
    st.title("⚙️ Admin Panel")
    st.write("This section is for administrative tasks, user management, and system monitoring.")

    if st.session_state.get('user_role') != 'admin':
        st.error("Access Denied: You must be an administrator to view this page.")
        return

    # --- User Management Section ---
    st.subheader("User Management")

    try:
        if st.button("🔄 Refresh User List"):
            st.rerun()

        # This method 'get_all_users_for_admin' needs to be created in your SecurityCore class.
        # It should return a list of user dictionaries.
        users_data = security_core.get_all_users_for_admin()

        if not users_data:
            st.info("No users found in the system.")
            return

        # Explicitly define columns to display for security and clarity
        df = pd.DataFrame(users_data)
        display_columns = {
            'id': 'User ID',
            'first_name': 'First Name',
            'last_name': 'Last Name',
            'email': 'Email',
            'company': 'Company',
            'plan': 'Plan',
            'role': 'Role',
            'status': 'Status',
            'payment_status': 'Payment Status',
            'email_verified': 'Email Verified',
            'created_at': 'Created At',
            'last_login': 'Last Login'
        }
        
        # Filter dataframe to only include columns we want to show
        cols_to_show = [col for col in display_columns.keys() if col in df.columns]
        st.dataframe(df[cols_to_show].rename(columns=display_columns))

        st.markdown("---")
        st.subheader("Admin Actions")

        # Use an expander for a cleaner UI for actions
        with st.expander("✏️ Manage User Roles and View Events"):
            user_email_to_manage = st.text_input(
                "Enter user's email to manage:",
                help="Type the full email of the user you wish to manage and press Enter."
            )

            if user_email_to_manage:
                # CORRECTED: Changed to 'get_user_idby_email' to match security_core.py
                target_user = security_core.get_user_idby_email(user_email_to_manage)

                if target_user:
                    st.success(f"Selected User: **{target_user['first_name']} {target_user['last_name']}** ({target_user['email']})")
                    st.write(f"Current Role: **{target_user['role'].title()}** | Status: **{target_user['status'].title()}**")

                    # --- Role Management ---
                    col1, col2 = st.columns(2)
                    with col1:
                        if target_user['role'] != 'admin':
                            if st.button(f"Promote to Admin", key=f"promote_{target_user['id']}"):
                                if security_core.promote_to_admin(target_user['id']):
                                    st.success(f"{target_user['first_name']} has been promoted to Admin.")
                                    st.rerun()
                                else:
                                    st.error("Failed to promote user.")
                        else:
                            st.button("Promote to Admin", disabled=True, help="User is already an Admin.")

                    with col2:
                        if target_user['role'] != 'user':
                            if st.button(f"Demote to User", key=f"demote_{target_user['id']}"):
                                if security_core.demote_to_user(target_user['id']):
                                    st.success(f"{target_user['first_name']} has been demoted to User.")
                                    st.rerun()
                                else:
                                    st.error("Failed to demote user.")
                        else:
                            st.button("Demote to User", disabled=True, help="User is already a standard User.")
                    
                    # --- Security Event Viewer ---
                    st.markdown("---")
                    st.markdown("#### Security Events")
                    if st.button("Load Security Events for this User"):
                        events = security_core.get_security_events(target_user['id'], limit=50)
                        if events:
                            events_df = pd.DataFrame(events)
                            st.write(f"Displaying last {len(events)} events for {target_user['email']}:")
                            st.dataframe(events_df[['timestamp', 'event_type', 'severity', 'description', 'source_ip']])
                        else:
                            st.info("No security events found for this user.")

                else:
                    st.warning("No user found with that email address.")

    except Exception as e:
        logger.error(f"An error occurred in the admin panel: {e}", exc_info=True)
        st.error(f"An unexpected error occurred: {e}")
        st.warning("Please ensure the backend services and database are running correctly.")
