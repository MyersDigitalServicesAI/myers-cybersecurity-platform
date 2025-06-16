import pandas as pd
import streamlit as st
import logging

logger = logging.getLogger(__name__)

def show_admin_panel(security_core):
    st.title("⚙️ Admin Panel")

    user_role = st.session_state.get('user_role')
    if user_role != 'admin':
        st.error("Access Denied: You must be an administrator to view this page.")
        return

    st.subheader("Admin Actions")

    # Example: List all users (basic)
    st.markdown("---")
    st.subheader("User Management (Admin View)")
    if st.button("Refresh User List"):
        st.rerun() # Simple way to re-fetch data

    try:
        conn = security_core.get_connection() # Admin panel likely needs direct DB access via SecurityCore
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, company, plan, role, status, email_verified, payment_status FROM users ORDER BY created_at DESC;")
        users_data = cursor.fetchall()
        conn.close()

        if users_data:
            # Display users in a dataframe or table
            df = pd.DataFrame(users_data, columns=["ID", "Email", "Company", "Plan", "Role", "Status", "Email Verified", "Payment Status"])
            st.dataframe(df)

            # Example: Promote/Demote user
            st.markdown("#### Change User Role")
            user_to_change_email = st.text_input("Enter email of user to change role:")
            if user_to_change_email:
                target_user = security_core.get_user_by_email(user_to_change_email)
                if target_user:
                    st.write(f"Current role for {target_user['email']}: **{target_user['role']}**")
                    col_promote, col_demote = st.columns(2)
                    with col_promote:
                        if st.button(f"Promote {target_user['first_name']} to Admin", key=f"promote_{target_user['id']}"):
                            try:
                                security_core.promote_to_admin(target_user['id'])
                                st.success(f"{target_user['first_name']} promoted to admin.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error promoting user: {e}")
                    with col_demote:
                        if st.button(f"Demote {target_user['first_name']} to User", key=f"demote_{target_user['id']}"):
                            try:
                                security_core.demote_to_user(target_user['id'])
                                st.success(f"{target_user['first_name']} demoted to user.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error demoting user: {e}")
                else:
                    st.warning("User not found with that email.")
            else:
                st.info("Enter an email to manage user roles.")
        else:
            st.info("No users registered yet.")

    except Exception as e:
        logger.error(f"Error loading user data in admin panel: {e}", exc_info=True)
        st.error(f"Failed to load user data: {e}. Check database connection.")
        st.stop() # Can't proceed without DB

    st.markdown("---")
    st.subheader("System Logs (Coming Soon)")
    st.info("Detailed system activity and audit logs will be available here.")

    st.markdown("---")
    st.subheader("Global Settings (Coming Soon)")
    st.info("Configure application-wide settings and integrations.")
