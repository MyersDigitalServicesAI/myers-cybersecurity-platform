import pandas as pd
import streamlit as st
import logging

logger = logging.getLogger(__name__)

def show_admin_panel(security_core):
    st.title("⚙️ Admin Panel")
    st.write("This section is for administrative tasks and configurations.")
    
    user_role = st.session_state.get('user_role')
    if user_role != 'admin':
        st.error("Access Denied: You must be an administrator to view this page.")
        return

    st.subheader("User Management")
    if st.button("Refresh User List"):
        st.rerun()

    try:
        # CORRECTED: Using the abstraction layer instead of direct DB access.
        # This method 'get_all_users_for_admin' would need to be created in your SecurityCore class.
        users_data = security_core.get_all_users_for_admin()

        if users_data:
            df = pd.DataFrame(users_data) # Assuming the method returns a list of dicts
            st.dataframe(df)

            # --- User Role Management ---
            st.markdown("#### Change User Role")
            user_email_to_change = st.text_input("Enter email of user to change role:")
            
            if user_email_to_change:
                # This method should exist in SecurityCore to get user by email
                target_user = security_core.get_user_by_email(user_email_to_change)
                if target_user:
                    st.write(f"Current role for {target_user['email']}: **{target_user['role']}**")
                    
                    if target_user['role'] != 'admin':
                        if st.button(f"Promote {target_user['first_name']} to Admin", key=f"promote_{target_user['id']}"):
                            # This method should exist in SecurityCore
                            security_core.promote_to_admin(target_user['id'])
                            st.success(f"{target_user['first_name']} promoted to admin.")
                            st.rerun()
                    
                    if target_user['role'] != 'user':
                        if st.button(f"Demote {target_user['first_name']} to User", key=f"demote_{target_user['id']}"):
                            # This method should exist in SecurityCore
                            security_core.demote_to_user(target_user['id'])
                            st.success(f"{target_user['first_name']} demoted to user.")
                            st.rerun()
                else:
                    st.warning("User not found with that email.")
        else:
            st.info("No users registered yet.")
            
    except Exception as e:
        logger.error(f"Error loading user data in admin panel: {e}", exc_info=True)
        st.error(f"Failed to load user data: {e}. Ensure the backend service is running.")

