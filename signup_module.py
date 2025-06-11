import streamlit as st
import secrets
import string

def generate_temp_password(length=16):
    """
    Generate a secure random password of specified length.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def show_signup_page():
    """Show signup form for a SaaS onboarding flow"""
    st.markdown("## Start Your 30-Day Free Trial")
    
    # Promo banner
    st.markdown("""
    <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                padding: 1rem; border-radius: 8px; margin: 1rem 0; text-align: center; color: white;">
        <h4 style="margin: 0; color: white;">⚡ Limited Time Offer!</h4>
        <p style="margin: 0.5rem 0; color: white;">
            Sign up within 15 days of your trial and get <strong>25% OFF</strong> your first year!
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Pick plan from session or use default
    selected_plan = st.session_state.get('selected_plan', 'professional')
    plan_names = {
        'essentials': "Essentials",
        'basic': "Basic",
        'professional': "Professional",
        'business': "Business",
        'enterprise': "Enterprise"
    }
    st.markdown(f"### Selected Plan: **{plan_names.get(selected_plan, selected_plan.title())}**")

    with st.form("signup_form"):
        col1, col2 = st.columns(2)
        with col1:
            company_name = st.text_input("Company Name *")
            first_name = st.text_input("First Name *")
            last_name = st.text_input("Last Name *")
        with col2:
            email = st.text_input("Email Address *")
            phone = st.text_input("Phone Number")
            job_title = st.text_input("Job Title")
        st.markdown(
            'By signing up, you agree to our '
            '[Terms of Service](#) and [Privacy Policy](#).',
            unsafe_allow_html=True
        )
        agreed = st.checkbox("I agree to the Terms of Service and Privacy Policy *", value=False)
        submitted = st.form_submit_button("Start Free Trial", type="primary", use_container_width=True)

        if submitted:
            # Validate required fields
            fields_required = [company_name, first_name, last_name, email]
            if all(fields_required) and agreed:
                # Use a secure random password for initial setup (change in real app)
                temp_password = generate_temp_password()
                try:
                    # You must have a security_core object in st.session_state
                    user_id = st.session_state.security_core.create_user(
                        email=email,
                        password=temp_password,
                        company=company_name,
                        first_name=first_name,
                        last_name=last_name,
                        plan=selected_plan,
                        phone=phone,
                        job_title=job_title
                    )
                except Exception as e:
                    user_id = None
                    st.error(f"Internal error: {e}")

                if user_id:
                    st.session_state.authenticated = True
                    st.session_state.user_id = user_id
                    st.session_state.user_email = email
                    st.session_state.user_role = 'user'
                    st.session_state.company_name = company_name
                    st.session_state.selected_plan = selected_plan
                    st.session_state.first_name = first_name
                    st.session_state.last_name = last_name

                    # Log signup
                    st.session_state.security_core.log_security_event(
                        user_id=user_id,
                        event_type="user_signup",
                        severity="info",
                        description="New user signed up for trial"
                    )

                    # Show success and proceed
                    st.success("Welcome to Myers Cybersecurity! Your 30-day trial is now active.")
                    st.balloons()
                    st.session_state.current_page = 'dashboard'
                    st.rerun()
                else:
                    st.error("Email address already exists. Please use a different email or login.")
            else:
                st.error("Please fill in all required fields and agree to the terms.")

# Only run the signup page if this file is the main
if __name__ == "__main__":
    # For demo/testing, put a mock security_core in session state
    class MockSecurityCore:
        def __init__(self):
            self._users = {}
        def create_user(self, **kwargs):
            if kwargs['email'] in self._users:
                return None
            user_id = secrets.token_hex(8)
            self._users[kwargs['email']] = dict(id=user_id, **kwargs)
            return user_id
        def log_security_event(self, **kwargs):
            print("Security Event:", kwargs)
    if 'security_core' not in st.session_state:
        st.session_state.security_core = MockSecurityCore()
    show_signup_page()
