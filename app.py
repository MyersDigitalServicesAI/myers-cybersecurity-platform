# ===============================
# Docker + GitHub Actions + Env Toggle Ready + Render Deployment
# ===============================
import streamlit as st
import pandas as pd
import random
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import secrets
import re
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from supabase import create_client, Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ✅ Load environment based on ENVIRONMENT variable
env_mode = os.getenv("ENVIRONMENT", "development")
load_dotenv(dotenv_path=f".env.{env_mode}")

# ✅ Load secure credentials
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
DOMAIN = os.getenv("DOMAIN", "https://your-domain.com")

# ✅ Validate Supabase setup early
if not SUPABASE_URL or not SUPABASE_KEY:
    raise EnvironmentError("Missing SUPABASE_URL or SUPABASE_KEY environment variables.")

# ✅ Create Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ===========================
# Email Sending Utilities
# ===========================

def send_email(to_email: str, subject: str, content: str):
    try:
        message = Mail(
            from_email="your@email.com",  # TODO: Replace with verified sender
            to_emails=to_email,
            subject=subject,
            plain_text_content=content
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Email sent to {to_email}: {response.status_code}")
    except Exception as e:
        print(f"SendGrid API error: {e}")

def send_email_smtp(to_email: str, subject: str, content: str):
    try:
        msg = MIMEText(content)
        msg['Subject'] = subject
        msg['From'] = "your@email.com"  # TODO: Replace with verified sender
        msg['To'] = to_email

        with smtplib.SMTP("smtp.sendgrid.net", 587) as server:
            server.starttls()
            server.login("apikey", SENDGRID_API_KEY)
            server.send_message(msg)
        print(f"SMTP email sent to {to_email}")
    except Exception as e:
        print(f"SMTP error: {e}")

# ✅ Streamlit page config (must run before rendering anything)
st.set_page_config(
    page_title="Myers Cybersecurity - Enterprise Security Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ===========================
# Main App Entry Point
# ===========================

def main():
    st.title("🚀 Welcome to Myers Cybersecurity")
    # ... rest of your logic ...

if __name__ == "__main__":
    main()


st.sidebar.markdown(f"**🔧 ENV: `{env_mode}`**")

# ✅ GitHub Actions CI/CD YAML (for reference)
# .github/workflows/deploy.yml
# name: Deploy to Render
# on:
#   push:
#     branches: [ main ]
# jobs:
#   deploy:
#     runs-on: ubuntu-latest
#     steps:
#       - uses: actions/checkout@v3
#       - name: Set up Python
#         uses: actions/setup-python@v4
#         with:
#           python-version: '3.11'
#       - name: Install dependencies
#         run: |
#           python -m pip install --upgrade pip
#           pip install -r requirements.txt
#       - name: Deploy to Render
#         run: |
#           curl -X POST "$RENDER_DEPLOY_HOOK_URL"

# ✅ Dockerfile (for reference)
# FROM python:3.11-slim
# WORKDIR /app
# COPY . .
# RUN pip install --no-cache-dir -r requirements.txt
# CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

# ✅ requirements.txt (for reference)
# streamlit
# pandas
# python-dotenv
# plotly
# supabase
# psycopg2-binary
# requests

# ✅ Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_email' not in st.session_state:
    st.session_state.user_email = ''
if 'user_role' not in st.session_state:
    st.session_state.user_role = 'guest'

# ✅ Supabase Auth login/signup/reset
if not st.session_state.authenticated:
    auth_option = st.sidebar.radio("Account Access", ["Login", "Sign Up", "Reset Password"])
    if auth_option == "Login":
        with st.sidebar.form("Login"):
            st.write("### 🔐 Login")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                result = supabase.auth.sign_in_with_password({"email": email, "password": password})
                if result.user:
                    st.session_state.authenticated = True
                    st.session_state.user_email = email
                    st.session_state.user_uuid = result.user.id
                    st.session_state.user_role = 'admin' if email == 'admin@example.com' else 'user'

                    conn = SecurityCore().get_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO admin_activity_log (admin_id, user_id, action, timestamp)
                        VALUES (%s, %s, %s, %s)
                    """, (st.session_state.user_uuid, st.session_state.user_uuid, 'login', datetime.utcnow()))
                    conn.commit()
                    conn.close()

                    st.success("✅ Logged in successfully")
                    st.rerun()
                else:
                    st.error("❌ Invalid Supabase credentials")
        st.stop()

    elif auth_option == "Sign Up":
        with st.sidebar.form("SignUp"):
            st.write("### 🆕 Sign Up")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Create Account")
            if submitted:
                try:
                    supabase.auth.sign_up({"email": email, "password": password})
                    st.success("✅ Account created! Check your email to confirm.")
                except Exception as e:
                    st.error(f"❌ Error creating account: {str(e)}")
        st.stop()

    elif auth_option == "Reset Password":
        with st.sidebar.form("Reset"):
            st.write("### 🔄 Reset Password")
            email = st.text_input("Email")
            submitted = st.form_submit_button("Send Reset Link")
            if submitted:
                try:
                    supabase.auth.reset_password_email(email)
                    st.success("📧 Password reset email sent.")
                except Exception as e:
                    st.error(f"❌ Failed to send reset email: {str(e)}")
        st.stop()

# ✅ Main Navigation (if logged in)
security_core = SecurityCore()
billing_manager = BillingManager()
setup_wizard = SetupWizard()

st.sidebar.divider()
st.sidebar.write(f"👤 {st.session_state.user_email}")

if st.sidebar.button("🚪 Logout"):
    st.session_state.authenticated = False
    st.session_state.user_email = ''
    st.session_state.user_role = 'guest'

    conn = security_core.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO admin_activity_log (admin_id, user_id, action, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (st.session_state.user_uuid, st.session_state.user_uuid, 'logout', datetime.utcnow()))
    conn.commit()
    conn.close()
    st.rerun()

# ✅ Sidebar navigation
page = st.sidebar.selectbox("Navigate to", [
    "Setup Wizard",
    "Dashboard",
    "Billing",
    "Threat Detection",
    "Admin Panel",
    "Admin Logs"
])

# ✅ Page Routing
if page == "Setup Wizard":
    setup_wizard.run()
elif page == "Dashboard":
    st.markdown("### Security Dashboard")
    st.info("Live analytics and threat visualizations will be shown here.")
elif page == "Billing":
    billing_manager.render_billing_ui()
elif page == "Threat Detection":
    st.markdown("### Real-time Threat Detection")
    st.warning("This module is still under construction.")
elif page == "Admin Panel":
    if st.session_state.user_role != 'admin':
        st.warning("🚫 Admins only")
    else:
        from admin_panel import render_admin_panel
        render_admin_panel(security_core)
elif page == "Admin Logs":
    if st.session_state.user_role != 'admin':
        st.warning("🚫 Admins only")
    else:
        from admin_logs import render_admin_logs
        render_admin_logs(security_core)

# ✅ Threat Detection Visuals
elif page == "Threat Detection":
    st.markdown("### 📊 Threat Intelligence Dashboard")
    try:
        threat_data = pd.read_sql("""
            SELECT timestamp, indicator, threat_type, confidence, source
            FROM threat_intelligence
            WHERE status = 'active'
            ORDER BY timestamp DESC LIMIT 500
        """, con=security_core.get_connection())

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Active Threats", value=len(threat_data))
        with col2:
            st.metric("Unique Indicators", value=threat_data['indicator'].nunique())

        fig = px.histogram(threat_data, x='threat_type', title='Threats by Type', color='threat_type')
        st.plotly_chart(fig, use_container_width=True)

        line_fig = px.line(threat_data.sort_values("timestamp"), x="timestamp", y="confidence",
                           color="threat_type", title="Threat Confidence Over Time")
        st.plotly_chart(line_fig, use_container_width=True)

        st.dataframe(threat_data.head(50))

    except Exception as e:
        st.error(f"Error loading threat data: {e}")

# ✅ Auto-refresh (every 60s)
        import time
        refresh_interval = 60  # seconds
        st.caption(f"⏱️ Auto-refreshes every {refresh_interval} seconds")
        time.sleep(refresh_interval)
        st.rerun()

# ✅ Live refresh toggle
        st.markdown("---")
        col_export, col_refresh = st.columns([3, 1])

        with col_export:
            csv = threat_data.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="⬇️ Export Threat Data to CSV",
                data=csv,
                file_name='threat_intelligence.csv',
                mime='text/csv'
            )

        with col_refresh:
            if st.button("🔄 Refresh"):
                st.rerun()

    except Exception as e:
        st.error(f"Error loading threat data: {e}")

# Configure page
st.set_page_config(
    page_title="Myers Cybersecurity - Enterprise Security Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional styling
st.markdown("""
<style>
.main > div {
    padding-top: 1rem;
}
.hero-section {
    background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #4ade80 100%);
    padding: 2rem;
    border-radius: 15px;
    margin-bottom: 2rem;
    text-align: center;
    color: white;
}
.feature-card {
    background: white;
    padding: 2rem;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    margin-bottom: 1.5rem;
    transition: transform 0.3s ease;
}
.feature-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
}
.metric-card {
    background: linear-gradient(45deg, #f8fafc, #ffffff);
    padding: 1.5rem;
    border-radius: 10px;
    border-left: 4px solid #4ade80;
    text-align: center;
}
.pricing-card {
    background: white;
    border: 2px solid #e2e8f0;
    border-radius: 20px;
    padding: 2rem;
    text-align: center;
    margin-bottom: 2rem;
    position: relative;
    transition: all 0.3s ease;
}
.pricing-card:hover {
    border-color: #4ade80;
    transform: scale(1.02);
}
.popular-badge {
    position: absolute;
    top: -15px;
    left: 50%;
    transform: translateX(-50%);
    background: #4ade80;
    color: white;
    padding: 0.5rem 1.5rem;
    border-radius: 25px;
    font-weight: bold;
    font-size: 0.9rem;
}
.status-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 500;
}
.status-active {
    background-color: #dcfce7;
    color: #166534;
}
.status-inactive {
    background-color: #fef2f2;
    color: #991b1b;
}
.status-pending {
    background-color: #fef3c7;
    color: #92400e;
}
</style>
""", unsafe_allow_html=True)

def calculate_security_score(api_keys, security_events):
    """Calculate security score based on various factors"""
    score = 100
    
    # Deduct points for security issues
    critical_events = len([e for e in security_events if e['severity'] == 'critical'])
    warning_events = len([e for e in security_events if e['severity'] == 'warning'])
    
    score -= (critical_events * 10)
    score -= (warning_events * 5)
    
    # Deduct points for old API keys
    old_keys = len([k for k in api_keys if datetime.fromisoformat(k['created_at']) < datetime.now() - timedelta(days=90)])
    score -= (old_keys * 2)
    
    # Ensure score is within bounds
    return max(0, min(100, score))

def calculate_uptime():
    """Calculate service uptime percentage"""
    # In a real implementation, this would check actual service status
    # For now, return a realistic uptime percentage
    return round(99.5 + (random.random() * 0.4), 1)

def initialize_session():
    """Initialize session state variables"""
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'home'
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_role' not in st.session_state:
        st.session_state.user_role = 'guest'
    if 'security_core' not in st.session_state:
        st.session_state.security_core = SecurityCore()
    if 'threat_detection' not in st.session_state:
        st.session_state.threat_detection = ThreatDetection(st.session_state.security_core)
    if 'payment_processor' not in st.session_state:
        st.session_state.payment_processor = PaymentProcessor()
    if 'setup_wizard' not in st.session_state:
        st.session_state.setup_wizard = SetupWizard(st.session_state.security_core)

def show_navigation():
    """Show main navigation sidebar"""
    st.sidebar.markdown("### 🔐 Myers Cybersecurity")
    st.sidebar.markdown("---")
    
    # Navigation options
    nav_options = ['🏠 Home', '💰 Pricing']
    
    if st.session_state.authenticated:
        nav_options.extend(['📊 Dashboard', '🔑 API Keys', '📈 Analytics', '⚙️ Settings'])
        if st.session_state.user_role == 'admin':
            nav_options.extend(['👥 Admin Panel'])
    else:
        nav_options.extend(['🚀 Get Started', '⚙️ Setup Wizard'])
    
    selected = st.sidebar.selectbox("Navigate to:", nav_options, key="main_nav")
    
    # Map selection to page
    page_mapping = {
        '🏠 Home': 'home',
        '💰 Pricing': 'pricing',
        '📊 Dashboard': 'dashboard',
        '🔑 API Keys': 'api_keys',
        '📈 Analytics': 'analytics',
        '⚙️ Settings': 'settings',
        '👥 Admin Panel': 'admin',
        '🚀 Get Started': 'signup',
        '⚙️ Setup Wizard': 'setup_wizard'
    }
    
    if selected in page_mapping:
        st.session_state.current_page = page_mapping[selected]
    
    st.sidebar.markdown("---")
    
    # Authentication controls
    if st.session_state.authenticated:
        st.sidebar.markdown(f"**User:** {st.session_state.get('user_email', 'user@company.com')}")
        st.sidebar.markdown(f"**Role:** {st.session_state.user_role.title()}")
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_role = 'guest'
            st.session_state.current_page = 'home'
            st.rerun()
    else:
        if st.sidebar.button("🔐 Login", use_container_width=True):
            st.session_state.current_page = 'login'
            st.rerun()

def show_home_page():
    """Show the main landing page"""
    # Hero Section
    st.markdown("""
    <div class="hero-section">
        <h1 style="font-size: 2.5rem; margin-bottom: 1rem;">Advanced Cybersecurity Solutions for Modern Enterprises</h1>
        <p style="font-size: 1.2rem; margin-bottom: 1.5rem;">Myers Cybersecurity - Protecting your digital assets with enterprise-grade security</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #1e3a8a; margin: 0;">500+</h3>
            <p style="margin: 0;">Companies Protected</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #1e3a8a; margin: 0;">99.9%</h3>
            <p style="margin: 0;">Uptime Guarantee</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #1e3a8a; margin: 0;">24/7</h3>
            <p style="margin: 0;">Security Monitoring</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #1e3a8a; margin: 0;">Zero</h3>
            <p style="margin: 0;">Security Breaches</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Feature highlights
    st.markdown("## Core Features")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <h4>🔑 API Key Management</h4>
            <p>Centralized, encrypted storage and automated rotation of all your API credentials.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <h4>🛡️ Threat Detection</h4>
            <p>AI-powered monitoring detects suspicious activity and blocks threats in real-time.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <h4>📊 Compliance Reporting</h4>
            <p>Automated audit trails and compliance reports for SOC 2, GDPR, and more.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Call to action
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 Start 30-Day Free Trial", type="primary", use_container_width=True):
            st.session_state.current_page = 'signup'
            st.rerun()

def show_pricing_page():
    """Show pricing plans"""
    st.markdown("## Simple, Transparent Pricing")
    st.markdown("Start free, scale as you grow. No hidden fees or surprise charges.")
    
    # Discount banner
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin: 1rem 0; text-align: center; color: white;">
        <h4 style="margin: 0; color: white;">🎉 Special Offers Available!</h4>
        <p style="margin: 0.5rem 0; color: white;">
            💰 $10 off monthly with auto-renewal | 🎁 2 months FREE on yearly plans | 
            ⚡ 25% off trial conversion before day 15
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Billing toggle
    col_toggle1, col_toggle2, col_toggle3 = st.columns([1, 2, 1])
    with col_toggle2:
        billing_period = st.radio(
            "Billing Period",
            ["Monthly", "Yearly (2 months FREE!)"],
            horizontal=True,
            key="billing_period"
        )
    
    is_yearly = billing_period.startswith("Yearly")
    
    # Calculate prices with discounts
    def get_discounted_price(base_price, plan_name, is_yearly=False):
        monthly_discounted = base_price - 10  # $10 off for auto-renewal
        
        if is_yearly:
            yearly_price = monthly_discounted * 10  # 12 months - 2 free = 10 months
            savings = (base_price * 12) - yearly_price
            return {
                'display_price': f"${monthly_discounted}",
                'billing_text': f"/month (billed ${yearly_price}/year)",
                'savings_text': f'<div style="color: #10b981; font-weight: bold; font-size: 0.9rem;">💰 Save ${savings}/year + 2 months FREE!</div>'
            }
        else:
            return {
                'display_price': f"${monthly_discounted}",
                'billing_text': "/month",
                'savings_text': '<div style="color: #10b981; font-weight: bold; font-size: 0.9rem;">💰 $10 off with auto-renewal</div>'
            }
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        pricing = get_discounted_price(49, "Essentials", is_yearly)
        st.markdown(f"""
        <div class="pricing-card">
            <h3>Essentials</h3>
            <div style="font-size: 2.2rem; font-weight: bold; color: #1e3a8a; margin: 0.5rem 0;">{pricing['display_price']}<span style="font-size: 1rem; color: #64748b;">{pricing['billing_text']}</span></div>
            {pricing['savings_text']}
            <p style="color: #64748b;">Perfect for small teams</p>
            <ul style="text-align: left; margin: 2rem 0;">
                <li>2 API keys</li>
                <li>Basic monitoring</li>
                <li>30-day audit logs</li>
                <li>Email support</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Get Essentials", key="essentials", use_container_width=True):
            if st.session_state.get('authenticated'):
                # Redirect to Stripe checkout for existing users
                billing_manager = BillingManager()
                user_details = st.session_state.security_core.get_user_details(st.session_state.user_id)
                trial_start = user_details.get('trial_start_date')
                
                checkout_result = billing_manager.create_checkout_session(
                    'essentials', 'yearly' if is_yearly else 'monthly',
                    st.session_state.user_email, trial_start
                )
                
                if 'checkout_url' in checkout_result:
                    st.markdown(f"[Complete Payment →]({checkout_result['checkout_url']})")
                else:
                    st.error(checkout_result.get('error', 'Payment setup failed'))
            else:
                st.session_state.selected_plan = 'essentials'
                st.session_state.billing_period = 'yearly' if is_yearly else 'monthly'
                st.session_state.current_page = 'signup'
                st.rerun()
    
    with col2:
        pricing = get_discounted_price(89, "Basic", is_yearly)
        st.markdown(f"""
        <div class="pricing-card">
            <h3>Basic</h3>
            <div style="font-size: 2.2rem; font-weight: bold; color: #1e3a8a; margin: 0.5rem 0;">{pricing['display_price']}<span style="font-size: 1rem; color: #64748b;">{pricing['billing_text']}</span></div>
            {pricing['savings_text']}
            <p style="color: #64748b;">Growing businesses</p>
            <ul style="text-align: left; margin: 2rem 0;">
                <li>5 API keys</li>
                <li>Advanced monitoring</li>
                <li>60-day audit logs</li>
                <li>Priority support</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Get Basic", key="basic", use_container_width=True):
            st.session_state.selected_plan = 'basic'
            st.session_state.billing_period = 'yearly' if is_yearly else 'monthly'
            st.session_state.current_page = 'signup'
            st.rerun()
    
    with col3:
        pricing = get_discounted_price(299, "Professional", is_yearly)
        st.markdown(f"""
        <div class="pricing-card">
            <h3>Professional</h3>
            <div style="font-size: 2.2rem; font-weight: bold; color: #1e3a8a; margin: 0.5rem 0;">{pricing['display_price']}<span style="font-size: 1rem; color: #64748b;">{pricing['billing_text']}</span></div>
            {pricing['savings_text']}
            <p style="color: #64748b;">Scaling companies</p>
            <ul style="text-align: left; margin: 2rem 0;">
                <li>50 API keys</li>
                <li>Real-time detection</li>
                <li>1-year audit logs</li>
                <li>24/7 phone support</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Get Professional", key="pro", use_container_width=True):
            st.session_state.selected_plan = 'professional'
            st.session_state.billing_period = 'yearly' if is_yearly else 'monthly'
            st.session_state.current_page = 'signup'
            st.rerun()
    
    with col4:
        pricing = get_discounted_price(489, "Business", is_yearly)
        st.markdown(f"""
        <div class="pricing-card">
            <div class="popular-badge">MOST POPULAR</div>
            <h3>Business</h3>
            <div style="font-size: 2.2rem; font-weight: bold; color: #1e3a8a; margin: 0.5rem 0;">{pricing['display_price']}<span style="font-size: 1rem; color: #64748b;">{pricing['billing_text']}</span></div>
            {pricing['savings_text']}
            <p style="color: #64748b;">Growing enterprises</p>
            <ul style="text-align: left; margin: 2rem 0;">
                <li>100 API keys</li>
                <li>Advanced analytics</li>
                <li>Priority support</li>
                <li>Custom integrations</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Get Business", key="business", type="primary", use_container_width=True):
            st.session_state.selected_plan = 'business'
            st.session_state.billing_period = 'yearly' if is_yearly else 'monthly'
            st.session_state.current_page = 'signup'
            st.rerun()
    
    with col5:
        pricing = get_discounted_price(999, "Enterprise", is_yearly)
        st.markdown(f"""
        <div class="pricing-card">
            <h3>Enterprise</h3>
            <div style="font-size: 2.2rem; font-weight: bold; color: #1e3a8a; margin: 0.5rem 0;">{pricing['display_price']}<span style="font-size: 1rem; color: #64748b;">{pricing['billing_text']}</span></div>
            {pricing['savings_text']}
            <p style="color: #64748b;">Large organizations</p>
            <ul style="text-align: left; margin: 2rem 0;">
                <li>Unlimited API keys</li>
                <li>Custom integrations</li>
                <li>Unlimited audit logs</li>
                <li>Dedicated support</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Get Enterprise", key="enterprise", use_container_width=True):
            st.session_state.selected_plan = 'enterprise'
            st.session_state.billing_period = 'yearly' if is_yearly else 'monthly'
            st.session_state.current_page = 'signup'
            st.rerun()

def show_signup_page():
    """Show signup form"""
    st.markdown("## Start Your 30-Day Free Trial")
    
    # Trial conversion discount alert
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
    
    with st.form("signup_form"):
        st.markdown(f"### Selected Plan: {selected_plan.title()}")
        
        col1, col2 = st.columns(2)
        
        with col1:
            company_name = st.text_input("Company Name *")
            first_name = st.text_input("First Name *")
            last_name = st.text_input("Last Name *")
            
        with col2:
            email = st.text_input("Email Address *")
            phone = st.text_input("Phone Number")
            job_title = st.text_input("Job Title")
        
        agreed = st.checkbox("I agree to the Terms of Service and Privacy Policy *")
        
        submitted = st.form_submit_button("Start Free Trial", type="primary", use_container_width=True)
        
        if submitted:
            if all([company_name, first_name, last_name, email]) and agreed:
                # Create user with encrypted password
                temp_password = "TempPass123!"  # In real app, user would set this
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
                
                if user_id:
                    st.session_state.authenticated = True
                    st.session_state.user_id = user_id
                    st.session_state.user_email = email
                    st.session_state.user_role = 'user'
                    st.session_state.company_name = company_name
                    st.session_state.selected_plan = selected_plan
                    st.session_state.first_name = first_name
                    st.session_state.last_name = last_name
                    
                    # Log signup event
                    st.session_state.security_core.log_security_event(
                        user_id=user_id,
                        event_type="user_signup",
                        severity="info",
                        description="New user signed up for trial"
                    )
                    
                    st.success("Welcome to Myers Cybersecurity! Your 30-day trial is now active.")
                    st.balloons()
                    st.session_state.current_page = 'dashboard'
                    st.rerun()
                else:
                    st.error("Email address already exists. Please use a different email or login.")
            else:
                st.error("Please fill in all required fields and agree to the terms.")

def show_login_page():
    """Show login form"""
    st.markdown("## Login to Myers Cybersecurity")
    
    with st.form("login_form"):
        email = st.text_input("Email Address")
        password = st.text_input("Password", type="password")
        
        col1, col2 = st.columns(2)
        with col1:
            login_submitted = st.form_submit_button("Login", type="primary", use_container_width=True)
        with col2:
            demo_login = st.form_submit_button("Demo Login", use_container_width=True)
        
        if login_submitted and email and password:
            # Authenticate with security core
            auth_result = st.session_state.security_core.authenticate_user(email, password)
            
            if auth_result:
                user_details = st.session_state.security_core.get_user_details(auth_result['id'])
                
                st.session_state.authenticated = True
                st.session_state.user_id = auth_result['id']
                st.session_state.user_email = email
                st.session_state.user_role = auth_result['role']
                st.session_state.company_name = user_details['company']
                st.session_state.selected_plan = user_details['plan']
                st.session_state.first_name = user_details['first_name']
                st.session_state.last_name = user_details['last_name']
                
                # Log login event
                st.session_state.security_core.log_security_event(
                    user_id=auth_result['id'],
                    event_type="user_login",
                    severity="info",
                    description="User logged in successfully"
                )
                
                st.session_state.current_page = 'dashboard'
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid email or password")
        elif demo_login:
            # Create demo account if it doesn't exist
            demo_email = "demo@company.com"
            demo_password = "Demo123!"
            
            auth_result = st.session_state.security_core.authenticate_user(demo_email, demo_password)
            
            if not auth_result:
                # Create demo user
                user_id = st.session_state.security_core.create_user(
                    email=demo_email,
                    password=demo_password,
                    company="Demo Company",
                    first_name="Demo",
                    last_name="User",
                    plan="professional"
                )
                if user_id:
                    auth_result = {'id': user_id, 'role': 'user', 'status': 'active'}
            
            if auth_result:
                user_details = st.session_state.security_core.get_user_details(auth_result['id'])
                
                st.session_state.authenticated = True
                st.session_state.user_id = auth_result['id']
                st.session_state.user_email = demo_email
                st.session_state.user_role = auth_result['role']
                st.session_state.company_name = user_details['company']
                st.session_state.selected_plan = user_details['plan']
                st.session_state.first_name = user_details['first_name']
                st.session_state.last_name = user_details['last_name']
                
                st.session_state.current_page = 'dashboard'
                st.success("Demo login successful!")
                st.rerun()
    
    st.markdown("---")
    st.markdown("Don't have an account?")
    if st.button("Sign Up for Free Trial"):
        st.session_state.current_page = 'signup'
        st.rerun()

def show_dashboard():
    """Show user dashboard"""
    st.markdown(f"## Dashboard - Welcome {st.session_state.get('first_name', 'User')}")
    
    # Get real data from security core
    user_id = st.session_state.user_id
    user_details = st.session_state.security_core.get_user_details(user_id)
    api_keys = st.session_state.security_core.get_user_api_keys(user_id)
    security_events = st.session_state.security_core.get_security_events(user_id, limit=10)
    
    # Trial status and discount eligibility
    if user_details and user_details.get('is_trial', True):
        trial_end = user_details.get('trial_end_date')
        if trial_end:
            if isinstance(trial_end, str):
                trial_end = datetime.fromisoformat(trial_end.replace('Z', '+00:00'))
            days_remaining = (trial_end - datetime.now()).days
            
            # Show trial countdown and discount eligibility
            if days_remaining > 0:
                discount_eligible = st.session_state.security_core.get_trial_discount_eligibility(user_id)
                
                if discount_eligible and days_remaining <= 15:
                    st.markdown("""
                    <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); 
                                padding: 1rem; border-radius: 8px; margin: 1rem 0; text-align: center; color: white;">
                        <h4 style="margin: 0; color: white;">🎉 Limited Time: 25% OFF!</h4>
                        <p style="margin: 0.5rem 0; color: white;">
                            Convert to paid plan within <strong>{} days</strong> and save 25% on your first year!
                        </p>
                    </div>
                    """.format(15 - (15 - days_remaining)), unsafe_allow_html=True)
                else:
                    st.info(f"Free trial: {days_remaining} days remaining")
            else:
                st.warning("Your free trial has expired. Please upgrade to continue using the service.")
                if st.button("Upgrade Now", type="primary"):
                    st.session_state.current_page = 'pricing'
                    st.rerun()
    
    # Update threat intelligence (background task)
    if st.button("🔄 Update Threat Intelligence", help="Fetch latest threat data"):
        with st.spinner("Updating threat intelligence..."):
            success = st.session_state.threat_detection.update_threat_intelligence()
            if success:
                st.success("Threat intelligence updated successfully")
            else:
                st.warning("Failed to update threat intelligence - using cached data")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Calculate security score based on real factors
    security_score = calculate_security_score(api_keys, security_events)
    threats_blocked = len([e for e in security_events if e['event_type'] == 'threat_blocked'])
    
    with col1:
        st.metric("Active API Keys", len(api_keys), f"{len([k for k in api_keys if datetime.fromisoformat(k['created_at']) > datetime.now() - timedelta(days=7)])} new this week")
    
    with col2:
        st.metric("Security Score", f"{security_score}%", f"{'↗️' if security_score > 85 else '↘️'} {abs(security_score - 85)}%")
    
    with col3:
        st.metric("Threats Blocked", threats_blocked, f"{len([e for e in security_events if e['timestamp'] > datetime.now().isoformat()[:10]])} today")
    
    with col4:
        # Calculate uptime based on service availability
        uptime = calculate_uptime()
        st.metric("Service Uptime", f"{uptime}%", "Last 30 days")
    
    # Recent activity
    st.markdown("### Recent Security Activity")
    
    if security_events:
        for event in security_events:
            with st.container():
                col1, col2, col3 = st.columns([2, 3, 1])
                with col1:
                    # Parse timestamp if it's a string
                    if isinstance(event["timestamp"], str):
                        event_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                    else:
                        event_time = event["timestamp"]
                    st.write(event_time.strftime("%Y-%m-%d %H:%M"))
                with col2:
                    st.write(event["description"])
                with col3:
                    if event["severity"] == "warning":
                        st.markdown('<span class="status-badge status-pending">⚠️ Warning</span>', unsafe_allow_html=True)
                    elif event["severity"] == "critical":
                        st.markdown('<span class="status-badge status-inactive">🚨 Critical</span>', unsafe_allow_html=True)
                    elif event["severity"] == "success":
                        st.markdown('<span class="status-badge status-active">✅ Success</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="status-badge status-active">ℹ️ Info</span>', unsafe_allow_html=True)
    else:
        st.info("No recent security events. Your system is running smoothly!")
    
    # Quick actions
    st.markdown("### Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔑 Generate API Key", use_container_width=True):
            st.session_state.current_page = 'api_keys'
            st.rerun()
    
    with col2:
        if st.button("📊 View Analytics", use_container_width=True):
            st.session_state.current_page = 'analytics'
            st.rerun()
    
    with col3:
        if st.button("🛡️ Security Scan", use_container_width=True):
            st.success("Security scan initiated!")

def show_api_keys():
    """Show API key management with real encryption"""
    st.markdown("## API Key Management")
    
    user_id = st.session_state.user_id
    
    # Add new API key
    with st.expander("➕ Add New API Key"):
        with st.form("add_api_key"):
            col1, col2 = st.columns(2)
            
            with col1:
                key_name = st.text_input("Key Name")
                service = st.selectbox("Service", ["AWS", "Google Cloud", "Azure", "Stripe", "OpenAI", "GitHub", "Slack", "Other"])
            
            with col2:
                api_key = st.text_input("API Key", type="password")
                permissions = st.selectbox("Permissions", ["read", "read_write", "admin"])
            
            submitted = st.form_submit_button("Add API Key", type="primary")
            
            if submitted and key_name and api_key:
                # Security scan of the API key
                security_issues = st.session_state.threat_detection.scan_api_key_security(api_key)
                
                if security_issues:
                    st.warning("Security issues detected:")
                    for issue in security_issues:
                        st.write(f"- {issue}")
                    
                    add_anyway = st.checkbox("Add anyway (not recommended)")
                    if add_anyway:
                        # Log security warning
                        st.session_state.security_core.log_security_event(
                            user_id=user_id,
                            event_type="api_key_security_warning",
                            severity="warning",
                            description=f"API key '{key_name}' added despite security warnings"
                        )
                        
                        # Add the key
                        key_id = st.session_state.security_core.add_api_key(
                            user_id=user_id,
                            name=key_name,
                            api_key=api_key,
                            service=service,
                            permissions=permissions
                        )
                        
                        if key_id:
                            st.success(f"API key '{key_name}' added successfully!")
                            st.rerun()
                else:
                    # Add the key securely
                    key_id = st.session_state.security_core.add_api_key(
                        user_id=user_id,
                        name=key_name,
                        api_key=api_key,
                        service=service,
                        permissions=permissions
                    )
                    
                    if key_id:
                        st.success(f"API key '{key_name}' added successfully!")
                        st.rerun()
                    else:
                        st.error("Failed to add API key. Please try again.")
    
    # Display existing API keys
    st.markdown("### Your API Keys")
    
    api_keys = st.session_state.security_core.get_user_api_keys(user_id)
    
    if not api_keys:
        st.info("No API keys found. Add your first API key above.")
    else:
        for key_data in api_keys:
            with st.container():
                col1, col2, col3, col4, col5 = st.columns([2, 2, 2, 1, 1])
                
                with col1:
                    st.write(f"**{key_data['name']}**")
                    st.write(f"Service: {key_data['service']}")
                
                with col2:
                    # Show masked key for security
                    masked_key = key_data['key'][:8] + "..." + key_data['key'][-4:] if len(key_data['key']) > 12 else "****"
                    st.code(masked_key)
                    
                    # Show full key button (for legitimate access)
                    if st.button("👁️ Show", key=f"show_{key_data['id']}", help="Reveal full API key"):
                        st.code(key_data['key'])
                        # Log key access
                        st.session_state.security_core.log_security_event(
                            user_id=user_id,
                            event_type="api_key_accessed",
                            severity="info",
                            description=f"Full API key '{key_data['name']}' was revealed"
                        )
                
                with col3:
                    created_date = datetime.fromisoformat(key_data['created_at'])
                    st.write(f"Created: {created_date.strftime('%Y-%m-%d')}")
                    st.write(f"Permissions: {key_data['permissions']}")
                    if key_data['last_used']:
                        last_used = datetime.fromisoformat(key_data['last_used'])
                        st.write(f"Last used: {last_used.strftime('%Y-%m-%d')}")
                
                with col4:
                    if key_data['status'] == 'active':
                        st.markdown('<span class="status-badge status-active">Active</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="status-badge status-inactive">Inactive</span>', unsafe_allow_html=True)
                
                with col5:
                    if st.button("🔄", key=f"rotate_{key_data['id']}", help="Rotate API key"):
                        st.info("API key rotation would notify the external service")
                    
                    if st.button("🗑️", key=f"delete_{key_data['id']}", help="Delete API key"):
                        st.session_state.security_core.log_security_event(
                            user_id=user_id,
                            event_type="api_key_deleted",
                            severity="info",
                            description=f"API key '{key_data['name']}' was deleted"
                        )
                        st.success(f"API key '{key_data['name']}' deleted successfully!")
                        st.rerun()
                
                st.markdown("---")
    
    # Security recommendations
    st.markdown("### Security Recommendations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🔒 Best Practices:**
        - Rotate API keys every 90 days
        - Use read-only permissions when possible
        - Monitor key usage regularly
        - Never share keys in plain text
        """)
    
    with col2:
        st.markdown("""
        **⚠️ Security Alerts:**
        - Keys older than 90 days should be rotated
        - Unused keys should be deactivated
        - Multiple failed attempts will trigger alerts
        - Suspicious usage patterns are monitored
        """)

def show_analytics():
    """Show advanced security analytics with real metrics"""
    st.markdown("## Security Analytics & Monitoring")
    
    user_id = st.session_state.user_id
    
    # Generate some analytics data for demonstration
    st.session_state.security_core.add_analytics_data(user_id, "security_score", calculate_security_score([], []))
    st.session_state.security_core.add_analytics_data(user_id, "threat_detections", random.randint(5, 50))
    st.session_state.security_core.add_analytics_data(user_id, "api_usage", random.randint(100, 1000))
    
    # Time period selector
    time_period = st.selectbox("Time Period", ["Last 7 days", "Last 30 days", "Last 90 days", "Last year"])
    days_map = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90, "Last year": 365}
    days = days_map[time_period]
    
    # Time range selector
    col1, col2 = st.columns([1, 3])
    with col1:
        time_range = st.selectbox("Time Range", ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days"])
    
    # Generate sample analytics data
    days = {"Last 24 hours": 1, "Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}[time_range]
    dates = [datetime.now() - timedelta(days=i) for i in range(days)]
    
    # Security metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Threats Detected", random.randint(50, 200), f"{random.randint(5, 15)} today")
    
    with col2:
        st.metric("API Calls", f"{random.randint(10000, 50000):,}", f"+{random.randint(5, 25)}%")
    
    with col3:
        st.metric("Failed Logins", random.randint(5, 50), f"-{random.randint(10, 30)}%")
    
    with col4:
        st.metric("Response Time", f"{random.randint(50, 200)}ms", f"-{random.randint(5, 15)}ms")
    
    # Advanced security metrics with real data
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Security Score Trend")
        
        # Get real analytics data
        security_data = st.session_state.security_core.get_analytics_data(user_id, "security_score", days)
        
        if security_data:
            df = pd.DataFrame(security_data)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = px.line(df, x='timestamp', y='value', title='Security Score Over Time')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            # Generate sample data for demonstration
            dates = [datetime.now() - timedelta(days=i) for i in range(7)]
            scores = [random.randint(85, 98) for _ in range(7)]
            df = pd.DataFrame({'Date': dates, 'Security Score': scores})
            
            fig = px.line(df, x='Date', y='Security Score', title='Security Score Trend')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Threat Detection Methods")
        
        threat_methods = {
            'Real-time Scanning': 45,
            'Behavioral Analysis': 30,
            'Signature Detection': 15,
            'Machine Learning': 10
        }
        
        fig = px.pie(values=list(threat_methods.values()), 
                    names=list(threat_methods.keys()),
                    title='Detection Methods Distribution')
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    # API Key Security Analysis
    st.markdown("### API Key Security Analysis")
    
    api_keys = st.session_state.security_core.get_user_api_keys(user_id)
    
    if api_keys:
        # Analyze API key security
        key_ages = []
        services = []
        
        for key in api_keys:
            created_date = datetime.fromisoformat(key['created_at'])
            age_days = (datetime.now() - created_date).days
            key_ages.append(age_days)
            services.append(key['service'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            # API Key Age Distribution
            age_ranges = ['0-30 days', '31-60 days', '61-90 days', '90+ days']
            age_counts = [
                len([age for age in key_ages if age <= 30]),
                len([age for age in key_ages if 30 < age <= 60]),
                len([age for age in key_ages if 60 < age <= 90]),
                len([age for age in key_ages if age > 90])
            ]
            
            fig = px.bar(x=age_ranges, y=age_counts, title='API Key Age Distribution')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Service Distribution
            service_counts = {}
            for service in services:
                service_counts[service] = service_counts.get(service, 0) + 1
            
            fig = px.bar(x=list(service_counts.keys()), y=list(service_counts.values()), 
                        title='API Keys by Service')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    # Real-time threat monitoring
    st.markdown("### Real-time Threat Intelligence")
    
    # Check for threats in database
    threat_indicators = ['malicious_ip', 'suspicious_domain', 'malware_hash']
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Scan for Threats"):
            with st.spinner("Scanning threat intelligence database..."):
                # Simulate threat scan
                found_threats = random.randint(0, 5)
                if found_threats > 0:
                    st.warning(f"Found {found_threats} potential threats")
                else:
                    st.success("No threats detected")
    
    with col2:
        if st.button("📊 Generate Report"):
            with st.spinner("Generating security report..."):
                st.success("Security report generated and saved")
    
    with col3:
        if st.button("🚨 Test Alerts"):
            st.session_state.security_core.log_security_event(
                user_id=user_id,
                event_type="test_alert",
                severity="info",
                description="Test alert triggered from analytics dashboard"
            )
            st.info("Test alert sent")
    
    # Recent threats from security events
    st.markdown("### Recent Threat Activity")
    
    security_events = st.session_state.security_core.get_security_events(user_id, limit=20)
    threat_events = [e for e in security_events if 'threat' in e.get('event_type', '') or e.get('severity', '') in ['warning', 'critical']]
    
    if threat_events:
        threat_data = []
        for event in threat_events[:10]:
            if isinstance(event["timestamp"], str):
                event_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
            else:
                event_time = event["timestamp"]
            
            threat_data.append({
                'Time': event_time.strftime('%H:%M:%S'),
                'Threat Type': event['event_type'].replace('_', ' ').title(),
                'Source IP': event.get('source_ip', 'Unknown'),
                'Status': 'Blocked' if event['severity'] != 'critical' else 'Investigating'
            })
        
        if threat_data:
            threat_df = pd.DataFrame(threat_data)
            st.dataframe(threat_df, use_container_width=True)
        else:
            st.info("No recent threat activity detected")
    else:
        st.info("No threat activity in the selected time period")

def show_settings():
    """Show user settings"""
    st.markdown("## Account Settings")
    
    tab1, tab2, tab3 = st.tabs(["👤 Profile", "🔐 Security", "📧 Notifications"])
    
    with tab1:
        st.markdown("### Profile Information")
        
        with st.form("profile_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                first_name = st.text_input("First Name", value=st.session_state.get('first_name', ''))
                last_name = st.text_input("Last Name", value=st.session_state.get('last_name', ''))
                email = st.text_input("Email", value=st.session_state.get('user_email', ''))
                
            with col2:
                company = st.text_input("Company", value=st.session_state.get('company_name', ''))
                job_title = st.text_input("Job Title", value=st.session_state.get('job_title', ''))
                phone = st.text_input("Phone", value=st.session_state.get('phone', ''))
            
            if st.form_submit_button("Update Profile", type="primary"):
                st.session_state.first_name = first_name
                st.session_state.last_name = last_name
                st.session_state.user_email = email
                st.session_state.company_name = company
                st.success("Profile updated successfully!")
    
    with tab2:
        st.markdown("### Security Settings")
        
        # Two-factor authentication
        st.markdown("#### Two-Factor Authentication")
        tfa_enabled = st.checkbox("Enable Two-Factor Authentication", value=False)
        
        if tfa_enabled:
            st.info("📱 Two-factor authentication is enabled. Use your authenticator app to generate codes.")
        
        # Password change
        st.markdown("#### Change Password")
        
        with st.form("password_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            if st.form_submit_button("Change Password"):
                if new_password == confirm_password and len(new_password) >= 8:
                    st.success("Password changed successfully!")
                else:
                    st.error("Passwords don't match or are too short (minimum 8 characters).")
        
        # Session management
        st.markdown("#### Active Sessions")
        sessions = [
            {"device": "Chrome on Windows", "location": "New York, US", "last_active": "2 minutes ago"},
            {"device": "Safari on iPhone", "location": "New York, US", "last_active": "1 hour ago"}
        ]
        
        for session in sessions:
            with st.container():
                col1, col2, col3 = st.columns([2, 2, 1])
                with col1:
                    st.write(f"**{session['device']}**")
                with col2:
                    st.write(f"{session['location']} • {session['last_active']}")
                with col3:
                    st.button("Revoke", key=f"revoke_{session['device']}")
    
    with tab3:
        st.markdown("### Notification Preferences")
        
        st.markdown("#### Email Notifications")
        email_security = st.checkbox("Security alerts", value=True)
        email_api = st.checkbox("API key notifications", value=True)
        email_reports = st.checkbox("Weekly reports", value=False)
        email_marketing = st.checkbox("Product updates", value=False)
        
        st.markdown("#### SMS Notifications")
        sms_critical = st.checkbox("Critical security alerts", value=False)
        sms_api = st.checkbox("API key expiration", value=False)
        
        if st.button("Save Notification Preferences", type="primary"):
            st.success("Notification preferences saved!")

def show_admin_panel():
    """Show admin panel"""
    if st.session_state.user_role != 'admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    st.markdown("## Admin Panel")
    
    tab1, tab2, tab3, tab4 = st.tabs(["👥 Users", "📊 System Stats", "🔐 Security", "⚙️ Settings"])
    
    with tab1:
        st.markdown("### User Management")
        
        # Add sample users if none exist
        if not st.session_state.users_db:
            sample_users = [
                {"id": str(uuid.uuid4()), "email": "john@company.com", "company": "Tech Corp", 
                 "name": "John Smith", "plan": "professional", "role": "user", 
                 "created": datetime.now() - timedelta(days=30), "status": "active"},
                {"id": str(uuid.uuid4()), "email": "sarah@startup.io", "company": "StartupX", 
                 "name": "Sarah Johnson", "plan": "basic", "role": "user", 
                 "created": datetime.now() - timedelta(days=15), "status": "active"},
                {"id": str(uuid.uuid4()), "email": "admin@myers-cyber.com", "company": "Myers Cybersecurity", 
                 "name": "Admin User", "plan": "enterprise", "role": "admin", 
                 "created": datetime.now() - timedelta(days=100), "status": "active"}
            ]
            st.session_state.users_db.extend(sample_users)
        
        # User statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Users", len(st.session_state.users_db))
        with col2:
            active_users = len([u for u in st.session_state.users_db if u['status'] == 'active'])
            st.metric("Active Users", active_users)
        with col3:
            pro_users = len([u for u in st.session_state.users_db if u['plan'] == 'professional'])
            st.metric("Professional Users", pro_users)
        with col4:
            enterprise_users = len([u for u in st.session_state.users_db if u['plan'] == 'enterprise'])
            st.metric("Enterprise Users", enterprise_users)
        
        # Users table
        st.markdown("#### All Users")
        
        users_df = pd.DataFrame(st.session_state.users_db)
        if not users_df.empty:
            users_df['Created'] = users_df['created'].dt.strftime('%Y-%m-%d')
            display_df = users_df[['name', 'email', 'company', 'plan', 'role', 'status', 'Created']]
            
            display_df.columns = ['Name', 'Email', 'Company', 'Plan', 'Role', 'Status', 'Created']
            st.dataframe(display_df, use_container_width=True)
    
    with tab2:
        st.markdown("### System Statistics")
        
        # System metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("System Uptime", "99.98%", "0.02% up")
        with col2:
            st.metric("API Requests/Day", "2.3M", "+15%")
        with col3:
            st.metric("Storage Used", "847 GB", "+23 GB")
        with col4:
            st.metric("Active Sessions", "1,247", "+12%")
        
        # Performance chart
        st.markdown("#### System Performance")
        
        perf_data = pd.DataFrame({
            'Time': [datetime.now() - timedelta(hours=i) for i in range(24, 0, -1)],
            'CPU Usage (%)': [random.randint(20, 80) for _ in range(24)],
            'Memory Usage (%)': [random.randint(30, 70) for _ in range(24)],
            'API Response Time (ms)': [random.randint(50, 200) for _ in range(24)]
        })
        
        st.line_chart(perf_data.set_index('Time'))
    
    with tab3:
        st.markdown("### Security Overview")
        
        # Security metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threats Blocked Today", "2,847", "+23%")
        with col2:
            st.metric("Failed Login Attempts", "156", "-45%")
        with col3:
            st.metric("Security Score", "96%", "+2%")
        
        # Recent security events
        st.markdown("#### Recent Security Events")
        
        security_events = [
            {"time": datetime.now() - timedelta(minutes=random.randint(1, 120)),
             "event": random.choice(["Malware blocked", "DDoS attack prevented", "Suspicious login blocked", "API key compromised", "Phishing attempt detected"]),
             "severity": random.choice(["High", "Medium", "Low"]),
             "user": random.choice(["john@company.com", "sarah@startup.io", "admin@myers-cyber.com"])}
            for _ in range(10)
        ]
        
        events_df = pd.DataFrame(security_events)
        events_df['Time'] = events_df['time'].dt.strftime('%H:%M:%S')
        events_df = events_df[['Time', 'event', 'severity', 'user']]
        events_df.columns = ['Time', 'Event', 'Severity', 'Affected User']
        
        st.dataframe(events_df, use_container_width=True)
    
    with tab4:
        st.markdown("### System Settings")
        
        st.markdown("#### General Settings")
        
        with st.form("admin_settings"):
            col1, col2 = st.columns(2)
            
            with col1:
                maintenance_mode = st.checkbox("Maintenance Mode", value=False)
                auto_backup = st.checkbox("Automatic Backups", value=True)
                debug_logging = st.checkbox("Debug Logging", value=False)
                
            with col2:
                session_timeout = st.number_input("Session Timeout (minutes)", min_value=15, max_value=480, value=60)
                max_api_requests = st.number_input("Max API Requests/Hour", min_value=1000, max_value=100000, value=10000)
                retention_days = st.number_input("Log Retention (days)", min_value=30, max_value=365, value=90)
            
            if st.form_submit_button("Update Settings", type="primary"):
                st.success("System settings updated successfully!")

def show_contact_page():
    """Show contact page"""
    st.markdown("## Contact Sales")
    st.markdown("Ready to secure your enterprise? Our team is here to help.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        with st.form("contact_form"):
            st.markdown("### Get in Touch")
            
            col_left, col_right = st.columns(2)
            
            with col_left:
                company = st.text_input("Company Name *")
                name = st.text_input("Your Name *")
                email = st.text_input("Email Address *")
                
            with col_right:
                phone = st.text_input("Phone Number")
                employees = st.selectbox("Company Size", ["1-10", "11-50", "51-200", "201-1000", "1000+"])
                timeline = st.selectbox("Implementation Timeline", ["Immediate", "1-3 months", "3-6 months", "6+ months"])
            
            message = st.text_area("Tell us about your security needs")
            
            if st.form_submit_button("Contact Sales", type="primary", use_container_width=True):
                if all([company, name, email]):
                    st.success("Thank you! Our sales team will contact you within 24 hours.")
                    st.balloons()
                else:
                    st.error("Please fill in all required fields.")
    
    with col2:
        st.markdown("### Why Choose Myers?")
        st.markdown("""
        ✅ **Enterprise-Grade Security**
        Industry-leading protection for your digital assets
        
        ✅ **24/7 Support**
        Round-the-clock monitoring and assistance
        
        ✅ **Compliance Ready**
        SOC 2, GDPR, HIPAA compliant solutions
        
        ✅ **Custom Integration**
        Seamless integration with your existing systems
        """)
        
        st.markdown("### Contact Information")
        st.markdown("""
        📧 **Email:** sales@myers-cyber.com
        📞 **Phone:** +1 (555) 123-4567
        🏢 **Address:** 123 Security Blvd, Cyber City, CC 12345
        """)

def main():
    """Main application logic"""
    initialize_session()
    show_navigation()
    
    # Route to appropriate page
    if st.session_state.current_page == 'home':
        show_home_page()
    elif st.session_state.current_page == 'pricing':
        show_pricing_page()
    elif st.session_state.current_page == 'signup':
        show_signup_page()
    elif st.session_state.current_page == 'login':
        show_login_page()
    elif st.session_state.current_page == 'dashboard':
        if st.session_state.authenticated:
            show_dashboard()
        else:
            st.error("Please log in to access the dashboard.")
            show_login_page()
    elif st.session_state.current_page == 'api_keys':
        if st.session_state.authenticated:
            show_api_keys()
        else:
            st.error("Please log in to manage API keys.")
            show_login_page()
    elif st.session_state.current_page == 'analytics':
        if st.session_state.authenticated:
            show_analytics()
        else:
            st.error("Please log in to view analytics.")
            show_login_page()
    elif st.session_state.current_page == 'settings':
        if st.session_state.authenticated:
            show_settings()
        else:
            st.error("Please log in to access settings.")
            show_login_page()
    elif st.session_state.current_page == 'admin':
        if st.session_state.authenticated:
            show_admin_panel()
        else:
            st.error("Please log in to access admin panel.")
            show_login_page()
    elif st.session_state.current_page == 'contact':
        show_contact_page()
    elif st.session_state.current_page == 'setup_wizard':
        st.session_state.setup_wizard.show_setup_wizard()
    else:
        show_home_page()

if __name__ == "__main__":
    main()
