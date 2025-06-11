import streamlit as st
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

# --- CONFIGURATION ---

SENDER_EMAIL = "noreply@yourdomain.com"
SMTP_SERVER = "smtp.sendgrid.net"
SMTP_PORT = 587
SMTP_USER = "apikey"
SMTP_API_KEY = "YOUR_SENDGRID_API_KEY"  # Set this securely, e.g. via os.getenv

APP_URL = "https://your-app.com"  # For the verification link

# --- HELPERS ---

def generate_temp_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_email_token(length=32):
    return secrets.token_urlsafe(length)

def send_verification_email(to_email, user_name, verification_link):
    subject = "Verify your email address"
    html = f"""\
    <html>
        <body>
            <p>Hello {user_name},<br>
            Thanks for signing up for Myers Cybersecurity.<br>
            Please verify your email by clicking the link below:<br>
            <a href="{verification_link}">{verification_link}</a>
            <br><br>
            If you did not sign up, please ignore this email.
            </p>
        </body>
    </html>
    """
    msg = MIMEText(html, "html")
    msg["Subject"] = subject
    msg["From"] = formataddr(("Myers Cybersecurity", SENDER_EMAIL))
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_API_KEY)
            server.send_message(msg)
        return True, ""
    except Exception as e:
        return False, str(e)

# --- MAIN SIGNUP FLOW ---

def show_signup_page():
    st.markdown("## Start Your 30-Day Free Trial")
    st.markdown("""
    <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                padding: 1rem; border-radius: 8px; margin: 1rem 0; text-align: center; color: white;">
        <h4 style="margin: 0; color: white;">⚡ Limited Time Offer!</h4>
        <p style="margin: 0.5rem 0; color: white;">
            Sign up within 15 days of your trial and get <strong>25% OFF</strong> your first year!
        </p>
    </div>
    """, unsafe_allow_html=True)
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
        st.markdown('By signing up, you agree to our [Terms of Service](#) and [Privacy Policy](#).', unsafe_allow_html=True)
        agreed = st.checkbox("I agree to the Terms of Service and Privacy Policy *", value=False)
        submitted = st.form_submit_button("Start Free Trial", type="primary", use_container_width=True)

        if submitted:
            fields_required = [company_name, first_name, last_name, email]
            if all(fields_required) and agreed:
                temp_password = generate_temp_password()
                email_token = generate_email_token(24)
                try:
                    # Save user as unverified in your DB (pseudo-code, replace with your own logic)
                    user_id = st.session_state.security_core.create_user(
                        email=email,
                        password=temp_password,
                        company=company_name,
                        first_name=first_name,
                        last_name=last_name,
                        plan=selected_plan,
                        phone=phone,
                        job_title=job_title,
                        email_token=email_token,
                        email_verified=False
                    )
                except Exception as e:
                    user_id = None
                    st.error(f"Internal error: {e}")

                if user_id:
                    verification_link = f"{APP_URL}/verify?token={email_token}&email={email}"
                    ok, err = send_verification_email(email, first_name, verification_link)
                    if ok:
                        st.session_state.pending_verification = {
                            "user_id": user_id,
                            "email": email
                        }
                        st.info("A verification email has been sent. Please check your inbox and click the verification link to activate your account.")
                        st.stop()
                    else:
                        st.error(f"Failed to send verification email: {err}")
                else:
                    st.error("Email address already exists. Please use a different email or login.")
            else:
                st.error("Please fill in all required fields and agree to the terms.")

def show_email_verification_page():
    st.markdown("## Email Verification")
    token = st.experimental_get_query_params().get("token", [None])[0]
    email = st.experimental_get_query_params().get("email", [None])[0]
    if token and email:
        # Check if token and email match a user in your DB (pseudo-code)
        user = st.session_state.security_core.get_user_by_email(email)
        if user and user.get("email_token") == token and not user.get("email_verified"):
            # Mark user as verified
            st.session_state.security_core.verify_user_email(user["id"])
            st.success("Your email has been verified! You can now log in.")
            st.session_state.current_page = "login"
            st.rerun()
        elif user and user.get("email_verified"):
            st.info("Your email is already verified. Please log in.")
        else:
            st.error("Invalid or expired verification link.")
    else:
        st.warning("Invalid verification URL.")

# --- MOCK IMPLEMENTATION FOR DEMO PURPOSES ---
class MockSecurityCore:
    def __init__(self):
        self._users = {}
    def create_user(self, **kwargs):
        if kwargs['email'] in self._users:
            return None
        user_id = secrets.token_hex(8)
        self._users[kwargs['email']] = dict(id=user_id, **kwargs)
        return user_id
    def get_user_by_email(self, email):
        return self._users.get(email, None)
    def verify_user_email(self, user_id):
        for user in self._users.values():
            if user["id"] == user_id:
                user["email_verified"] = True
                return True
        return False

# --- PAGE ROUTER FOR DEMO ---
def main():
    if 'security_core' not in st.session_state:
        st.session_state.security_core = MockSecurityCore()
    page = st.session_state.get("current_page", "signup")
    if page == "signup":
        show_signup_page()
    elif page == "verify":
        show_email_verification_page()
    else:
        st.write("Page not found.")

if __name__ == "__main__":
    main()
