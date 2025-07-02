import streamlit as st
import secrets
from datetime import datetime
from security_core import SecurityCore # Ensure this import is correct
from payment import PaymentProcessor # Ensure this import is correct

class SetupWizard:
    def __init__(self, security_core):
        self.security_core = security_core
        # PaymentProcessor can be initialized here if needed for fetching plans,
        # but actual checkout session creation might be handled elsewhere or in a later step.
        self.payment_processor = PaymentProcessor() 
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
            self.security_configuration_step()
        elif st.session_state.setup_step == 2:
            self.api_key_setup_step()
        elif st.session_state.setup_step == 3:
            self.payment_setup_step()
        elif st.session_state.setup_step == 4:
            self.final_review_step()
    
    def company_information_step(self):
        """Step 1: Collect company and admin information."""
        st.subheader("Tell us about your company and yourself.")
        
        # Initialize setup_data in session_state if not present
        if 'setup_data' not in st.session_state:
            st.session_state.setup_data = {}

        with st.form("company_info_form"):
            st.session_state.setup_data['company_name'] = st.text_input("Company Name", value=st.session_state.setup_data.get('company_name', ''))
            st.session_state.setup_data['admin_first_name'] = st.text_input("Admin First Name", value=st.session_state.setup_data.get('admin_first_name', ''))
            st.session_state.setup_data['admin_last_name'] = st.text_input("Admin Last Name", value=st.session_state.setup_data.get('admin_last_name', ''))
            st.session_state.setup_data['admin_email'] = st.text_input("Admin Email", value=st.session_state.setup_data.get('admin_email', ''))
            
            submitted = st.form_submit_button("Next")
            if submitted:
                if not st.session_state.setup_data['company_name']:
                    st.error("Company Name is required.")
                elif not st.session_state.setup_data['admin_first_name']:
                    st.error("Admin First Name is required.")
                elif not st.session_state.setup_data['admin_email']:
                    st.error("Admin Email is required.")
                elif not self.security_core.validate_email_input(st.session_state.setup_data['admin_email']):
                    st.error("Invalid Admin Email format.")
                else:
                    st.session_state.setup_step += 1
                    st.rerun()

    def security_configuration_step(self):
        """Step 2: Set up admin password and security preferences."""
        st.subheader("Set up your Admin Account Security.")

        with st.form("security_config_form"):
            admin_password = st.text_input("Admin Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            # Placeholder for security preferences (e.g., MFA, logging levels)
            st.markdown("---")
            st.write("Optional Security Preferences (can be configured later):")
            st.checkbox("Enable Multi-Factor Authentication (MFA) for Admin", value=False, disabled=True)
            st.selectbox("Default Logging Level", ["INFO", "WARNING", "ERROR", "CRITICAL"], index=0)

            submitted = st.form_submit_button("Next")
            if submitted:
                if not admin_password or not confirm_password:
                    st.error("Admin Password and Confirm Password are required.")
                elif admin_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    is_strong, msg = self.security_core.validate_password_strength(admin_password)
                    if not is_strong:
                        st.error(msg)
                    else:
                        st.session_state.setup_data['admin_password'] = admin_password
                        st.session_state.setup_step += 1
                        st.rerun()

    def api_key_setup_step(self):
        """Step 3: Generate initial API key."""
        st.subheader("Generate your first API Key.")
        st.info("This API key will be used to integrate with your systems. You can generate more later.")

        if 'initial_api_key' not in st.session_state.setup_data:
            st.session_state.setup_data['initial_api_key'] = ""
            st.session_state.setup_data['initial_api_key_name'] = "Default Admin Key"
            st.session_state.setup_data['initial_api_key_permissions'] = ["read", "write"]

        with st.form("api_key_form"):
            st.session_state.setup_data['initial_api_key_name'] = st.text_input(
                "API Key Name", 
                value=st.session_state.setup_data.get('initial_api_key_name', "Default Admin Key")
            )
            # Multi-select for permissions
            available_permissions = ["read", "write", "admin"]
            st.session_state.setup_data['initial_api_key_permissions'] = st.multiselect(
                "API Key Permissions",
                options=available_permissions,
                default=st.session_state.setup_data.get('initial_api_key_permissions', ["read", "write"])
            )
            
            submitted = st.form_submit_button("Generate Key & Next")
            if submitted:
                if not st.session_state.setup_data['initial_api_key_name']:
                    st.error("API Key Name is required.")
                elif not st.session_state.setup_data['initial_api_key_permissions']:
                    st.error("At least one permission must be selected for the API key.")
                else:
                    # Key generation will happen in final_review_step after user is created
                    st.session_state.setup_step += 1
                    st.rerun()

    def payment_setup_step(self):
        """Step 4: Select subscription plan."""
        st.subheader("Choose your Subscription Plan.")
        st.info("You can choose a plan now, or start with a trial if eligible. Payment details will be handled via Stripe.")

        # Fetch active prices from Stripe
        prices_response = self.payment_processor.get_active_prices()
        if prices_response.get("status") == "success":
            prices = prices_response.get("prices", [])
            if not prices:
                st.warning("No active subscription plans found. Please configure plans in Stripe.")
                st.session_state.setup_data['selected_plan'] = None
                st.session_state.setup_data['selected_price_id'] = None
                plan_options = ["No Plans Available"]
                plan_display_map = {}
            else:
                plan_options = []
                plan_display_map = {}
                for price in prices:
                    product_name = price.product.name
                    interval = price.recurring.interval
                    unit_amount = price.unit_amount / 100 # Convert cents to dollars
                    display_name = f"{product_name} - ${unit_amount:.2f}/{interval}"
                    plan_options.append(display_name)
                    plan_display_map[display_name] = price.id # Store Stripe Price ID

                # Add a "Start Trial" option if applicable and not already selected
                if "Start Trial (if eligible)" not in plan_options:
                    plan_options.insert(0, "Start Trial (if eligible)")
        else:
            st.error(f"Failed to retrieve subscription plans: {prices_response.get('error', 'Unknown error')}")
            st.warning("Proceeding without plan selection. Please configure Stripe and refresh.")
            plan_options = ["No Plans Available"]
            plan_display_map = {}


        with st.form("payment_setup_form"):
            selected_plan_display = st.selectbox(
                "Select a Plan or Start Trial",
                options=plan_options,
                index=0 # Default to "Start Trial" or first available plan
            )

            if selected_plan_display == "Start Trial (if eligible)":
                st.session_state.setup_data['selected_plan'] = "trial"
                st.session_state.setup_data['selected_price_id'] = None
                st.session_state.setup_data['is_trial_eligible'] = True
            elif selected_plan_display in plan_display_map:
                st.session_state.setup_data['selected_plan'] = selected_plan_display.split(" - ")[0].lower() # Extract plan name
                st.session_state.setup_data['selected_price_id'] = plan_display_map[selected_plan_display]
                st.session_state.setup_data['is_trial_eligible'] = False
            else:
                st.session_state.setup_data['selected_plan'] = None
                st.session_state.setup_data['selected_price_id'] = None
                st.session_state.setup_data['is_trial_eligible'] = False

            submitted = st.form_submit_button("Next")
            if submitted:
                if st.session_state.setup_data['selected_plan'] is None and "No Plans Available" not in plan_options:
                     st.error("Please select a plan or trial option.")
                else:
                    st.session_state.setup_step += 1
                    st.rerun()

    def final_review_step(self):
        """Step 5: Review all information and complete setup."""
        st.subheader("Final Review.")
        st.info("Please review all the details before completing the setup. This will create your admin account and initial API key.")

        setup_data = st.session_state.setup_data

        st.markdown("### Company Information")
        st.write(f"**Company Name:** {setup_data.get('company_name')}")
        st.write(f"**Admin Name:** {setup_data.get('admin_first_name')} {setup_data.get('admin_last_name')}")
        st.write(f"**Admin Email:** {setup_data.get('admin_email')}")

        st.markdown("### Security Configuration")
        st.write(f"**Admin Password Set:** {'Yes' if setup_data.get('admin_password') else 'No'}")

        st.markdown("### API Key Setup")
        st.write(f"**Initial API Key Name:** {setup_data.get('initial_api_key_name')}")
        st.write(f"**Initial API Key Permissions:** {', '.join(setup_data.get('initial_api_key_permissions', []))}")

        st.markdown("### Payment Setup")
        st.write(f"**Selected Plan:** {setup_data.get('selected_plan').title() if setup_data.get('selected_plan') else 'Not Selected'}")
        if setup_data.get('selected_plan') == 'trial':
            st.write("**Trial Eligible:** Yes")
        elif setup_data.get('selected_price_id'):
            st.write(f"**Stripe Price ID:** {setup_data.get('selected_price_id')}")

        st.markdown("---")

        if st.button("Complete Setup"):
            self.complete_setup(setup_data)

    def complete_setup(self, setup_data):
        """
        Finalizes the setup process: creates admin user, generates API key,
        and authenticates the user.
        """
        with st.spinner("Completing setup... This may take a moment."):
            # 1. Create Admin User
            user_id, msg = self.security_core.create_user(
                email=setup_data['admin_email'],
                password=setup_data['admin_password'],
                first_name=setup_data['admin_first_name'],
                last_name=setup_data['admin_last_name'],
                company_name=setup_data['company_name'],
                role='admin', # Ensure admin role is set
                plan=setup_data.get('selected_plan', 'essentials'),
                is_trial_eligible=setup_data.get('is_trial_eligible', False)
            )

            if user_id:
                st.success(f"Admin user created successfully: {setup_data['admin_email']}")
                
                # Update user's email verified status to True and status to 'active'
                self.security_core.update_user_email_verified_status(user_id, True)
                self.security_core.update_user_status(user_id, 'active') # Ensure status is active

                # 2. Generate and Store Initial API Key
                raw_api_key, encrypted_api_key = self.security_core.create_api_key(
                    user_id=user_id,
                    name=setup_data['initial_api_key_name'],
                    permissions=setup_data['initial_api_key_permissions']
                )
                if raw_api_key:
                    st.success("Initial API Key generated and stored.")
                    st.markdown(f"**Your Initial API Key (Keep this safe!):** `{raw_api_key}`")
                    st.session_state.setup_data['initial_api_key'] = raw_api_key # Store for display
                else:
                    st.error("Failed to generate initial API key.")

                # 3. Log Setup Completion Event
                self.security_core.log_security_event(
                    user_id=user_id,
                    event_type="setup_completed",
                    severity="info",
                    description="Initial platform setup completed successfully"
                )
                
                # Authenticate user and set session state for dashboard access
                st.session_state.authenticated = True
                st.session_state.user_id = user_id # Standardized to user_id
                st.session_state.user_email = setup_data['admin_email']
                st.session_state.user_role = 'admin'
                st.session_state.company_name = setup_data['company_name']
                st.session_state.selected_plan = setup_data['selected_plan']
                st.session_state.first_name = setup_data['admin_first_name']
                st.session_state.last_name = setup_data['admin_last_name']
                
                # Clean up setup data from session state
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
