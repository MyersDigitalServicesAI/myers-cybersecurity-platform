import streamlit as st
import secrets
from datetime import datetime
from security_core import SecurityCore, PaymentProcessor

class SetupWizard:
    def __init__(self, security_core):
        self.security_core = security_core
        self.steps = [
            "Company Information",
            "Security Configuration", 
            "API Key Setup",
            "Payment Setup",
            "Final Review"
        ]
    
    def show_setup_wizard(self):
        """Display the setup wizard interface"""
        if 'setup_step' not in st.session_state:
            st.session_state.setup_step = 0
        
        # Progress indicator
        progress = (st.session_state.setup_step + 1) / len(self.steps)
        st.progress(progress)
        
        current_step = self.steps[st.session_state.setup_step]
        st.markdown(f"## Setup Wizard - Step {st.session_state.setup_step + 1}: {current_step}")
        
        # Step content
        if st.session_state.setup_step == 0:
            self.company_information_step()
        elif st.session_state.setup_step == 1:
        elif st.session_state.setup_step == 2:
            self.api_key_setup_step()
        elif st.session_state.setup_step == 3:
            self.payment_setup_step()
        elif st.session_state.setup_step == 4:
            self.final_review_step()
    
    def company_information_step(self):
        """Step 1: Company information and admin account"""
        st.markdown("### Welcome to Myers Cybersecurity")
        st.markdown("Let's set up your enterprise security platform. This process takes about 5 minutes.")
        
        with st.form("company_setup"):
            col1, col2 = st.columns(2)
            
            with col1:
                company_name = st.text_input("Company Name *", help="Your organization's legal name")
                industry = st.selectbox("Industry", [
                    "Technology", "Healthcare", "Finance", "Manufacturing", 
                    "Retail", "Education", "Government", "Other"
                ])
                company_size = st.selectbox("Company Size", [
                    "1-10 employees", "11-50 employees", "51-200 employees",
                    "201-1000 employees", "1000+ employees"
                ])
            
            with col2:
                admin_email = st.text_input("Admin Email *", help="This will be your primary admin account")
                admin_password = st.text_input("Admin Password *", type="password", 
                                             help="Minimum 8 characters, include numbers and symbols")
                confirm_password = st.text_input("Confirm Password *", type="password")
            
            admin_first_name = st.text_input("Administrator First Name *")
            admin_last_name = st.text_input("Administrator Last Name *")
            
            compliance_requirements = st.multiselect("Compliance Requirements", [
                "SOC 2", "GDPR", "HIPAA", "PCI DSS", "ISO 27001", "NIST", "None"
            ])
            
            submitted = st.form_submit_button("Continue to Security Setup", type="primary")
            
            if submitted:
                if not all([company_name, admin_email, admin_password, admin_first_name, admin_last_name]):
                    st.error("Please fill in all required fields")
                elif admin_password != confirm_password:
                    st.error("Passwords do not match")
                elif len(admin_password) < 8:
                    st.error("Password must be at least 8 characters")
                else:
                    # Store setup data
                    st.session_state.setup_data = {
                        'company_name': company_name,
                        'industry': industry,
                        'company_size': company_size,
                        'admin_email': admin_email,
                        'admin_password': admin_password,
                        'admin_first_name': admin_first_name,
                        'admin_last_name': admin_last_name,
                        'compliance_requirements': compliance_requirements
                    }
                    st.session_state.setup_step = 1
                    st.rerun()
    
        st.markdown("### Security Configuration")
        st.markdown("Configure your security policies and monitoring preferences.")
        
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Authentication Settings**")
                require_2fa = st.checkbox("Require Two-Factor Authentication", value=True)
                password_policy = st.selectbox("Password Policy", [
                    "Standard (8+ chars)", "Enhanced (12+ chars + symbols)", 
                    "Enterprise (16+ chars + complexity)"
                ])
                session_timeout = st.selectbox("Session Timeout", [
                    "30 minutes", "1 hour", "4 hours", "8 hours", "24 hours"
                ])
            
            with col2:
                st.markdown("**Monitoring & Alerts**")
                threat_monitoring = st.checkbox("Real-time Threat Monitoring", value=True)
                api_monitoring = st.checkbox("API Key Usage Monitoring", value=True)
                anomaly_detection = st.checkbox("Behavioral Anomaly Detection", value=True)
                
                alert_channels = st.multiselect("Alert Channels", [
                    "Email", "SMS", "Slack", "Microsoft Teams", "Webhook"
                ])
            
            st.markdown("**Data Retention**")
            log_retention = st.selectbox("Security Log Retention", [
                "30 days", "90 days", "1 year", "2 years", "7 years"
            ])
            
            backup_frequency = st.selectbox("Backup Frequency", [
                "Daily", "Weekly", "Monthly"
            ])
            
            submitted = st.form_submit_button("Continue to API Setup", type="primary")
            
            if submitted:
                setup_data = st.session_state.setup_data
                setup_data.update({
                    'require_2fa': require_2fa,
                    'password_policy': password_policy,
                    'session_timeout': session_timeout,
                    'threat_monitoring': threat_monitoring,
                    'api_monitoring': api_monitoring,
                    'anomaly_detection': anomaly_detection,
                    'alert_channels': alert_channels,
                    'log_retention': log_retention,
                    'backup_frequency': backup_frequency
                })
                st.session_state.setup_data = setup_data
                st.session_state.setup_step = 2
                st.rerun()
    
    def api_key_setup_step(self):
        """Step 3: Initial API key setup"""
        st.markdown("### API Key Management Setup")
        
        with st.form("api_setup"):
            st.markdown("**Initial API Keys** (Optional - you can add these later)")
            
            num_keys = st.number_input("How many API keys do you want to add now?", 
                                     min_value=0, max_value=5, value=0)
            
            api_keys_data = []
            for i in range(int(num_keys)):
                st.markdown(f"**API Key {i+1}**")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    key_name = st.text_input(f"Name", key=f"key_name_{i}")
                with col2:
                    service = st.selectbox(f"Service", [
                        "AWS", "Google Cloud", "Azure", "Stripe", "OpenAI", 
                        "GitHub", "Slack", "Custom"
                    ], key=f"service_{i}")
                with col3:
                    api_key = st.text_input(f"API Key", type="password", key=f"api_key_{i}")
                
                if key_name and service and api_key:
                    api_keys_data.append({
                        'name': key_name,
                        'service': service,
                        'key': api_key
                    })
            
            st.markdown("**Automated Security Features**")
            col1, col2 = st.columns(2)
            
            with col1:
                auto_rotation = st.checkbox("Enable Automatic Key Rotation", value=True)
                rotation_frequency = st.selectbox("Rotation Frequency", [
                    "30 days", "60 days", "90 days", "180 days", "Annually"
                ])
            
            with col2:
                security_scanning = st.checkbox("Enable Security Scanning", value=True)
                leak_detection = st.checkbox("Enable Leak Detection", value=True)
            
            submitted = st.form_submit_button("Continue to Payment", type="primary")
            
            if submitted:
                setup_data = st.session_state.setup_data
                setup_data.update({
                    'api_keys_data': api_keys_data,
                    'auto_rotation': auto_rotation,
                    'rotation_frequency': rotation_frequency,
                    'security_scanning': security_scanning,
                    'leak_detection': leak_detection
                })
                st.session_state.setup_data = setup_data
                st.session_state.setup_step = 3
                st.rerun()
    
    def payment_setup_step(self):
        """Step 4: Payment and plan selection"""
        st.markdown("### Choose Your Plan")
        st.markdown("Select the plan that best fits your organization's needs.")
        
        # Plan comparison
        col1, col2, col3, col4 = st.columns(4)
        
        plans = {
            'essentials': {'price': 49, 'keys': 2, 'features': ['Basic monitoring', '30-day logs', 'Email support']},
            'basic': {'price': 89, 'keys': 5, 'features': ['Advanced monitoring', '60-day logs', 'Priority support']},
            'professional': {'price': 299, 'keys': 50, 'features': ['Real-time detection', '1-year logs', '24/7 support']},
            'enterprise': {'price': 999, 'keys': 'Unlimited', 'features': ['Custom integrations', 'Unlimited logs', 'Dedicated support']}
        }
        
        selected_plan = None
        
        with col1:
            if st.button("Essentials - $49/mo", key="plan_essentials"):
                selected_plan = 'essentials'
        
        with col2:
            if st.button("Basic - $89/mo", key="plan_basic"):
                selected_plan = 'basic'
        
        with col3:
            if st.button("Professional - $299/mo", key="plan_professional", type="primary"):
                selected_plan = 'professional'
        
        with col4:
            if st.button("Enterprise - $999/mo", key="plan_enterprise"):
                selected_plan = 'enterprise'
        
        if 'selected_plan' not in st.session_state:
            st.session_state.selected_plan = 'professional'
        
        if selected_plan:
            st.session_state.selected_plan = selected_plan
        
        current_plan = st.session_state.selected_plan
        st.info(f"Selected Plan: {current_plan.title()} - ${plans[current_plan]['price']}/month")
        
        with st.form("payment_setup"):
            st.markdown("**Billing Information**")
            
            col1, col2 = st.columns(2)
            with col1:
                billing_email = st.text_input("Billing Email", 
                                            value=st.session_state.setup_data.get('admin_email', ''))
                company_address = st.text_area("Company Address")
            
            with col2:
                billing_contact = st.text_input("Billing Contact Name")
                tax_id = st.text_input("Tax ID / VAT Number (Optional)")
            
            st.markdown("**Payment Method**")
            payment_method = st.radio("Payment Method", ["Credit Card", "Bank Transfer", "Invoice"])
            
            start_trial = st.checkbox("Start with 30-day free trial", value=True)
            
            submitted = st.form_submit_button("Continue to Review", type="primary")
            
            if submitted:
                setup_data = st.session_state.setup_data
                setup_data.update({
                    'selected_plan': current_plan,
                    'billing_email': billing_email,
                    'company_address': company_address,
                    'billing_contact': billing_contact,
                    'tax_id': tax_id,
                    'payment_method': payment_method,
                    'start_trial': start_trial
                })
                st.session_state.setup_data = setup_data
                st.session_state.setup_step = 4
                st.rerun()
    
    def final_review_step(self):
        """Step 5: Final review and setup completion"""
        st.markdown("### Setup Review")
        
        setup_data = st.session_state.setup_data
        
        # Display summary
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Company Information**")
            st.write(f"Company: {setup_data['company_name']}")
            st.write(f"Industry: {setup_data['industry']}")
            st.write(f"Size: {setup_data['company_size']}")
            st.write(f"Admin: {setup_data['admin_first_name']} {setup_data['admin_last_name']}")
            st.write(f"Email: {setup_data['admin_email']}")
            
            st.markdown("**Security Configuration**")
            st.write(f"2FA Required: {'Yes' if setup_data['require_2fa'] else 'No'}")
            st.write(f"Password Policy: {setup_data['password_policy']}")
            st.write(f"Session Timeout: {setup_data['session_timeout']}")
            st.write(f"Log Retention: {setup_data['log_retention']}")
        
        with col2:
            st.markdown("**Plan & Billing**")
            st.write(f"Plan: {setup_data['selected_plan'].title()}")
            st.write(f"Billing Email: {setup_data['billing_email']}")
            st.write(f"Payment Method: {setup_data['payment_method']}")
            st.write(f"Free Trial: {'Yes' if setup_data['start_trial'] else 'No'}")
            
            st.markdown("**API Keys**")
            if setup_data['api_keys_data']:
                for key_data in setup_data['api_keys_data']:
                    st.write(f"- {key_data['name']} ({key_data['service']})")
            else:
        
        # Terms and conditions
        st.markdown("---")
        terms_agreed = st.checkbox("I agree to the Terms of Service and Privacy Policy")
        setup_notifications = st.checkbox("Send me setup completion notifications", value=True)
        
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("Back to Payment", use_container_width=True):
                st.session_state.setup_step = 3
                st.rerun()
        
        with col2:
            if st.button("Complete Setup", type="primary", use_container_width=True, 
                        disabled=not terms_agreed):
                self.complete_setup()
        
        with col3:
            if st.button("Cancel Setup", use_container_width=True):
                if st.session_state.get('setup_data'):
                    del st.session_state.setup_data
                if st.session_state.get('setup_step'):
                    del st.session_state.setup_step
                st.session_state.current_page = 'home'
                st.rerun()
    
    def complete_setup(self):
        """Complete the setup process"""
        setup_data = st.session_state.setup_data
        
        try:
            # Create admin user
            user_id, msg = self.security_core.create_user(
                email=setup_data['admin_email'],
                password=setup_data['admin_password'],
                company=setup_data['company_name'],
                first_name=setup_data['admin_first_name'],
                last_name=setup_data['admin_last_name'],
                plan=setup_data['selected_plan']
            )
            
            if user_id:
                # Set admin role
                conn = self.security_core.get_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET role = %s WHERE id = %s', ('admin', user_id))
                conn.commit()
                conn.close()
                
                # Add initial API keys
                for key_data in setup_data['api_keys_data']:
                    self.security_core.add_api_key(
                        user_id=user_id,
                        name=key_data['name'],
                        api_key=key_data['key'],
                        service=key_data['service']
                    )
                
                # Log setup completion
                self.security_core.log_security_event(
                    user_id=user_id,
                    event_type="setup_completed",
                    severity="info",
                    description="Initial platform setup completed successfully"
                )
                
                # Authenticate user
                st.session_state.authenticated = True
                st.session_state.user_id = user_id
                st.session_state.user_email = setup_data['admin_email']
                st.session_state.user_role = 'admin'
                st.session_state.company_name = setup_data['company_name']
                st.session_state.selected_plan = setup_data['selected_plan']
                st.session_state.first_name = setup_data['admin_first_name']
                st.session_state.last_name = setup_data['admin_last_name']
                
                # Clean up setup data
                del st.session_state.setup_data
                del st.session_state.setup_step
                
                # Success message
                st.success("Setup completed successfully! Welcome to Myers Cybersecurity.")
                st.balloons()
                
                # Redirect to dashboard
                st.session_state.current_page = 'dashboard'
                st.rerun()
            else:
                st.error(f"Setup failed: {msg}")
                
        except Exception as e:
            st.error(f"Setup failed: {str(e)}")
