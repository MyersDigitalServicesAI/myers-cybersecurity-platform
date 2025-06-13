import os
import secrets
import json
import bcrypt
import re
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from email_validator import validate_email, EmailNotValidError
import logging
from functools import wraps
import random
from dotenv import load_dotenv
import psycopg2 

from utils.database import get_db_connection 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurable trial duration
DEFAULT_TRIAL_DAYS = int(os.getenv('DEFAULT_TRIAL_DAYS', 30))

def log_api_call(func):
    """Decorator to log API calls."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            # Log arguments skipping 'self' for instance methods
            logger.info(f"{func.__name__} called with args={args[1:]}, kwargs={kwargs} - SUCCESS")
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}", exc_info=True)
            raise
    return wrapper

class SecurityCore:
    def __init__(self):
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_database()

    def init_database(self):
        """
        Initializes the database schema, creating tables and columns if they don't exist.
        Includes schema for users, API keys, security events, threat intelligence,
        and processed webhook events.
        """
        conn = None
        try:
            conn = get_db_connection() 
            cursor = conn.cursor()

            # --- Users Table ---
            logger.info("Checking/Creating 'users' table and columns...")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(255) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    company VARCHAR(255) NOT NULL,
                    first_name VARCHAR(255) NOT NULL,
                    last_name VARCHAR(255) NOT NULL,
                    phone VARCHAR(50),
                    job_title VARCHAR(255),
                    plan VARCHAR(50) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    status VARCHAR(50) DEFAULT 'active',
                    trial_start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    trial_end_date TIMESTAMP,
                    is_trial BOOLEAN DEFAULT TRUE,
                    billing_period VARCHAR(20) DEFAULT 'monthly',
                    auto_renewal BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    trial_ends TIMESTAMP,
                    trial_token VARCHAR(255),
                    payment_status VARCHAR(50) DEFAULT 'trial',
                    email_token VARCHAR(255),
                    email_verified BOOLEAN DEFAULT FALSE,
                    subscription_id VARCHAR(255) UNIQUE NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Add missing columns to 'users' if they don't exist
            # Check for subscription_id
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'subscription_id';
            """)
            if not cursor.fetchone():
                logger.info("Adding subscription_id column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN subscription_id VARCHAR(255) UNIQUE NULL;")
                conn.commit()
            
            # Ensure 'status' column exists for users (e.g., active, inactive, suspended)
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'status';
            """)
            if not cursor.fetchone():
                logger.info("Adding status column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN status VARCHAR(50) DEFAULT 'active';")
                conn.commit()

            # --- API Keys Table ---
            logger.info("Checking/Creating 'api_keys' table...")
            cursor.execute('''CREATE TABLE IF NOT EXISTS api_keys (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                encrypted_key TEXT NOT NULL,
                service VARCHAR(255) NOT NULL,
                permissions VARCHAR(50) DEFAULT 'read',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP NULL, -- Added last_used column
                status VARCHAR(50) DEFAULT 'active' -- Added status column
            )''')

            # Add missing columns to 'api_keys' if they don't exist
            # Check for last_used
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'api_keys' AND column_name = 'last_used';
            """)
            if not cursor.fetchone():
                logger.info("Adding last_used column to api_keys table...")
                cursor.execute("ALTER TABLE api_keys ADD COLUMN last_used TIMESTAMP NULL;")
                conn.commit()

            # Check for status
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'api_keys' AND column_name = 'status';
            """)
            if not cursor.fetchone():
                logger.info("Adding status column to api_keys table...")
                cursor.execute("ALTER TABLE api_keys ADD COLUMN status VARCHAR(50) DEFAULT 'active';")
                conn.commit()


            # --- Security Events Table ---
            logger.info("Checking/Creating 'security_events' table...")
            cursor.execute('''CREATE TABLE IF NOT EXISTS security_events (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
                event_type VARCHAR(100),
                severity VARCHAR(50),
                description TEXT,
                source_ip VARCHAR(50),
                metadata JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT FALSE
            )''')

            # --- Threat Intelligence Table ---
            logger.info("Checking/Creating 'threat_intelligence' table...")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    indicator VARCHAR(255) UNIQUE NOT NULL, -- Added UNIQUE constraint
                    threat_type VARCHAR(100) NOT NULL,
                    confidence INTEGER,
                    source VARCHAR(100),
                    status VARCHAR(50) DEFAULT 'active',
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Add unique constraint to indicator if it doesn't exist
            try:
                cursor.execute("ALTER TABLE threat_intelligence ADD CONSTRAINT unique_indicator UNIQUE (indicator);")
                conn.commit()
                logger.info("Added unique_indicator constraint to threat_intelligence table.")
            except psycopg2.errors.DuplicateObject:
                conn.rollback() # Constraint already exists
                logger.info("unique_indicator constraint already exists on threat_intelligence table.")
            except Exception as e:
                logger.warning(f"Could not add unique_indicator constraint to threat_intelligence table: {e}")
                conn.rollback()


            # --- Processed Webhook Events Table (for Idempotency) ---
            logger.info("Checking/Creating 'processed_webhook_events' table...")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processed_webhook_events (
                    event_id VARCHAR(255) PRIMARY KEY,
                    event_type VARCHAR(100),
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            logger.info("Database initialization/migration complete.")
        except Exception as e:
            logger.critical(f"Database initialization failed: {e}", exc_info=True)
            raise
        finally:
            if conn:
                conn.close()

    def get_or_create_encryption_key(self):
        """Retrieves or generates the encryption key for API keys."""
        key_path = 'encryption.key'
        try:
            if os.path.exists(key_path):
                with open(key_path, 'rb') as key_file:
                    return Fernet(key_file.read())
            else:
                key = Fernet.generate_key()
                with open(key_path, 'wb') as key_file:
                    key_file.write(key)
                logger.info("New encryption key generated.")
                return Fernet(key)
        except IOError as e:
            logger.error(f"File I/O error with encryption key file '{key_path}': {e}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred getting/creating encryption key: {e}", exc_info=True)
            raise

    def hash_password(self, password):
        """Hashes a password using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password, hash_string):
        """Verifies a password against a hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_string.encode('utf-8'))
        except Exception:
            return False

    def validate_email_input(self, email):
        """Validates email format using email_validator."""
        try:
            validated_email = validate_email(email)
            return validated_email.email
        except EmailNotValidError:
            return None

    def validate_password_strength(self, password):
        """Validates password strength (length, uppercase, lowercase, digit)."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        return True, "Password is strong"

    def encrypt_api_key(self, api_key):
        """Encrypts an API key."""
        return self.encryption_key.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key):
        """Decrypts an API key."""
        try:
            return self.encryption_key.decrypt(encrypted_key.encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt API key: {e}. Key might be invalid or encryption key changed.", exc_info=True)
            return None

    @log_api_call
    def promote_to_admin(self, user_id):
        """Promotes a user to admin role."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE users SET role = 'admin', updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for promotion.")
                return False
            logger.info(f"User {user_id} promoted to admin.")
            return True
        except Exception as e:
            logger.error(f"Error promoting user {user_id} to admin: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    @log_api_call
    def demote_to_user(self, user_id):
        """Demotes an admin user to regular user role."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE users SET role = 'user', updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for demotion.")
                return False
            logger.info(f"User {user_id} demoted to user.")
            return True
        except Exception as e:
            logger.error(f"Error demoting user {user_id} to user: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    @log_api_call
    def deactivate_user_account(self, user_id):
        """Deactivates a user account (soft-deletion)."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE users SET status = 'inactive', updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for deactivation.")
                return False
            self.log_security_event(user_id, "user_account_deactivated", "info", f"User account {user_id} deactivated.")
            logger.info(f"User account {user_id} deactivated.")
            return True
        except Exception as e:
            logger.error(f"Error deactivating user account {user_id}: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_user(self, email, password, company, first_name, last_name, plan, phone="", job_title="", billing_period="monthly", email_token=None, email_verified=False, role='user', subscription_id=None, auto_renewal=True):
        """
        Creates a new user in the database.
        Includes initial trial setup and email verification status.
        """
        validated_email = self.validate_email_input(email)
        if not validated_email:
            return None, "Invalid email format"
        
        # Check if user already exists
        if self.get_user_by_email(validated_email):
            return None, "Email address already exists"
        
        company = self.sanitize_input(company, 255)
        first_name = self.sanitize_input(first_name, 255)
        last_name = self.sanitize_input(last_name, 255)
        phone = self.sanitize_input(phone, 50)
        job_title = self.sanitize_input(job_title, 255)
        
        allowed_plans = ['essentials', 'basic', 'professional', 'business', 'enterprise']
        if plan not in allowed_plans:
            return None, "Invalid plan selected"

        user_id = secrets.token_urlsafe(16)
        password_hash = self.hash_password(password)
        
        trial_start = datetime.now()
        trial_end = trial_start + timedelta(days=DEFAULT_TRIAL_DAYS) # Use configurable trial duration
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (id, email, password_hash, company, first_name, last_name,
                                 phone, job_title, plan, trial_start_date, trial_end_date,
                                 is_trial, billing_period, auto_renewal, trial_ends,
                                 email_token, email_verified, role, subscription_id, payment_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (user_id, validated_email, password_hash, company, first_name, last_name,
                  phone, job_title, plan, trial_start, trial_end, True, billing_period, auto_renewal, trial_end,
                  email_token, email_verified, role, subscription_id, 'trial' if email_verified else 'unverified'))
            conn.commit()
            logger.info(f"User {user_id} created successfully.")
            return user_id, "User created successfully"
        except psycopg2.IntegrityError as e:
            logger.error(f"Database integrity error in create_user: {e}", exc_info=True)
            conn.rollback()
            if "users_email_key" in str(e): # Specific check for email unique constraint
                 return None, "Email address already exists."
            return None, "Failed to create user account due to data conflict (e.g., email already exists)."
        except Exception as e:
            logger.error(f"Database error in create_user: {e}", exc_info=True)
            conn.rollback()
            return None, f"Database error: {str(e)}"
        finally:
            conn.close()

    def get_user_by_email(self, email):
        """Retrieves full user details by email."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, password_hash, company, first_name, last_name, phone, job_title,
                   plan, role, status, trial_ends, payment_status, email_token, email_verified,
                   is_trial, subscription_id, trial_start_date, auto_renewal
            FROM users WHERE email = %s
        ''', (email,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'id': result[0], 'email': result[1], 'password_hash': result[2],
                'company': result[3], 'first_name': result[4], 'last_name': result[5],
                'phone': result[6], 'job_title': result[7], 'plan': result[8],
                'role': result[9], 'status': result[10], 'trial_ends': result[11],
                'payment_status': result[12], 'email_token': result[13],
                'email_verified': result[14], 'is_trial': result[15],
                'subscription_id': result[16], 'trial_start_date': result[17],
                'auto_renewal': result[18] # Added auto_renewal
            }
        return None

    def get_user_details(self, user_id):
        """Retrieves select user details by ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, company, first_name, last_name, phone, job_title,
                   plan, role, status, trial_ends, payment_status, email_verified,
                   is_trial, subscription_id, trial_start_date, auto_renewal
            FROM users WHERE id = %s
        ''', (user_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'email': result[0], 'company': result[1], 'first_name': result[2],
                'last_name': result[3], 'phone': result[4], 'job_title': result[5],
                'plan': result[6], 'role': result[7], 'status': result[8],
                'trial_ends': result[9], 'payment_status': result[10],
                'email_verified': result[11], 'is_trial': result[12],
                'subscription_id': result[13], 'trial_start_date': result[14],
                'auto_renewal': result[15] # Added auto_renewal
            }
        return None

    def get_user_id_by_email(self, email):
        """Retrieves user ID by email."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def get_user_id_by_subscription_id(self, subscription_id):
        """Retrieves user ID by Stripe subscription ID."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE subscription_id = %s", (subscription_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def verify_user_email(self, user_id):
        """Marks a user's email as verified."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE users SET email_verified = TRUE, email_token = NULL, payment_status = 'trial', updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for email verification.")
                return False
            logger.info(f"Email verified for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error verifying user email {user_id}: {e}", exc_info=True)
            conn.rollback()
            return False
        finally:
            conn.close()

    def authenticate_user(self, email, password):
        """Authenticates a user by email and password."""
        user = self.get_user_by_email(email)
        if user and self.verify_password(password, user['password_hash']):
            if not user['email_verified']:
                return None, "Email not verified. Please check your inbox for the verification link."
            
            if user['status'] == 'inactive':
                return None, "Your account is inactive. Please contact support."

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute('UPDATE users SET last_login = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', (datetime.now(), user['id']))
                conn.commit()
                logger.info(f"User {user['id']} authenticated successfully.")
            except Exception as e:
                logger.error(f"Error updating last login for user {user['id']}: {e}", exc_info=True)
                conn.rollback()
            finally:
                conn.close()
            
            return {'id': user['id'], 'role': user['role'], 'status': user['status']}, None
        return None, "Invalid email or password."

    def update_user_subscription_status(self, user_id, payment_status, is_trial=None, subscription_id=None, trial_ends=None, auto_renewal=None):
        """
        Updates a user's payment and trial status based on webhook events.
        'trial_ends' will store the next billing date for paying customers.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            update_fields = []
            params = []

            update_fields.append("payment_status = %s")
            params.append(payment_status)

            if is_trial is not None:
                update_fields.append("is_trial = %s")
                params.append(is_trial)
            
            update_fields.append("subscription_id = %s")
            params.append(subscription_id)
            
            if trial_ends is not None:
                update_fields.append("trial_ends = %s")
                params.append(trial_ends)

            if auto_renewal is not None:
                update_fields.append("auto_renewal = %s")
                params.append(auto_renewal)

            update_fields.append("updated_at = CURRENT_TIMESTAMP")

            update_sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
            params.append(user_id)

            cursor.execute(update_sql, tuple(params))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for subscription status update.")
                return False
            logger.info(f"User {user_id} subscription status updated to {payment_status}. is_trial: {is_trial}, sub_id: {subscription_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating user {user_id} subscription status: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_trial_discount_eligibility(self, user_id):
        """Checks if a user is eligible for a trial conversion discount."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT trial_start_date, is_trial FROM users WHERE id = %s', (user_id,))
        result = cursor.fetchone()
        conn.close()
        if not result or not result[1]: # Not found or not currently on trial
            return False
        trial_start = result[0]
        days_since_trial = (datetime.now() - trial_start).days
        return days_since_trial <= 15 # Eligibility within first 15 days of trial

    def calculate_discounted_price(self, base_price, plan_name, billing_period="monthly", user_id=None):
        """Calculates pricing with potential discounts."""
        discounts = []
        final_monthly_base = base_price
        
        user_info = None
        if user_id:
            user_info = self.get_user_details(user_id) # Fetch user info to check auto_renewal

        # Auto-renewal discount conditional on user's auto_renewal setting
        if user_info and user_info.get('auto_renewal', False): # Assuming auto_renewal is a boolean field
            final_monthly_base -= 10
            discounts.append("$10 auto-renewal savings")

        monthly_price = final_monthly_base

        yearly_price = None
        total_savings = 0

        if billing_period == "yearly":
            yearly_price = final_monthly_base * 10 # Example: 2 months free for yearly
            yearly_savings_amount = (base_price * 12) - yearly_price
            discounts.append(f"2 months FREE (save ${yearly_savings_amount:.0f}/year)")
            total_savings += yearly_savings_amount

            if user_id and self.get_trial_discount_eligibility(user_id):
                trial_discount_amount = yearly_price * 0.25
                yearly_price -= trial_discount_amount
                discounts.append(f"25% trial conversion discount (save ${trial_discount_amount:.0f})")
                total_savings += trial_discount_amount

            return {
                'monthly_price': final_monthly_base, # Still show monthly rate for context
                'yearly_price': yearly_price,
                'total_savings': total_savings,
                'discounts': discounts
            }

        # Monthly billing period specific discounts
        if user_id and self.get_trial_discount_eligibility(user_id):
            # Apply 25% off for the first 3 months
            # This calculation assumes the "monthly_price" returned is the *initial* discounted monthly price
            # The actual recurring charge would revert after 3 months.
            # For simplicity, we calculate the total saving over 3 months here.
            trial_savings_monthly = monthly_price * 0.25 * 3
            discounts.append(f"25% off first 3 months (save ${trial_savings_monthly:.0f})")
            total_savings += trial_savings_monthly
            # If you want the monthly_price to reflect the discounted rate for the initial months,
            # you would do: monthly_price *= 0.75

        return {
            'monthly_price': monthly_price,
            'yearly_price': None,
            'total_savings': total_savings,
            'discounts': discounts
        }

    @log_api_call
    def add_api_key(self, user_id, name, api_key, service, permissions="read"):
        """Adds an encrypted API key for a user."""
        key_id = secrets.token_urlsafe(16)
        encrypted_key = self.encrypt_api_key(api_key)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO api_keys (id, user_id, name, encrypted_key, service, permissions, last_used, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (key_id, user_id, name, encrypted_key, service, permissions, datetime.now(), 'active'))
            conn.commit()
            self.log_security_event(user_id, "api_key_created", "info", f"API key '{name}' created for service '{service}'")
            logger.info(f"API key '{name}' added for user {user_id}.")
            return key_id
        except Exception as e:
            logger.error(f"Error adding API key for user {user_id}: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    @log_api_call
    def update_api_key_last_used(self, key_id):
        """Updates the last_used timestamp for an API key."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE api_keys SET last_used = %s WHERE id = %s
            """, (datetime.now(), key_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"API key {key_id} not found for last_used update.")
                return False
            return True
        except Exception as e:
            logger.error(f"Error updating last_used for API key {key_id}: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    @log_api_call
    def get_user_api_keys(self, user_id, include_inactive=False):
        """Retrieves and decrypts API keys for a user. Optionally includes inactive keys."""
        conn = get_db_connection()
        cursor = conn.cursor()
        query = 'SELECT id, name, encrypted_key, service, permissions, created_at, last_used, status FROM api_keys WHERE user_id = %s'
        params = [user_id]
        if not include_inactive:
            query += ' AND status = %s'
            params.append('active')

        cursor.execute(query, tuple(params))
        keys = cursor.fetchall()
        conn.close()
        
        decrypted_keys = []
        for row in keys:
            decrypted_key_value = self.decrypt_api_key(row[2])
            if decrypted_key_value: # Only include if decryption was successful
                decrypted_keys.append({
                    'id': row[0],
                    'name': row[1],
                    'key': decrypted_key_value,
                    'service': row[3],
                    'permissions': row[4],
                    'created_at': row[5],
                    'last_used': row[6],
                    'status': row[7]
                })
        return decrypted_keys

    @log_api_call
    def deactivate_api_key(self, key_id, user_id):
        """Deactivates an API key by ID for a specific user."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE api_keys SET status = 'inactive', created_at = CURRENT_TIMESTAMP WHERE id = %s AND user_id = %s
            """, (key_id, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                self.log_security_event(user_id, "api_key_deactivated", "info", f"API key '{key_id}' deactivated.")
                logger.info(f"API key '{key_id}' deactivated for user {user_id}.")
                return True
            else:
                logger.warning(f"Attempt to deactivate non-existent or unauthorized API key {key_id} for user {user_id}.")
                return False
        except Exception as e:
            logger.error(f"Error deactivating API key {key_id} for user {user_id}: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    def sanitize_input(self, val, maxlen):
        """Basic input sanitization."""
        if val is None:
            return ""
        return str(val).strip()[:maxlen] # Added .strip() for leading/trailing whitespace

    def log_security_event(self, user_id, event_type, severity, description, source_ip=None, metadata=None, resolved=False):
        """Logs a security event to the database."""
        event_id = secrets.token_urlsafe(16)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO security_events
                    (id, user_id, event_type, severity, description, source_ip, metadata, resolved)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (event_id, user_id, event_type, severity, description, source_ip, json.dumps(metadata) if metadata else None, resolved))
            conn.commit()
            logger.info(f"Security event '{event_type}' logged for user {user_id}.")
            return event_id
        except Exception as e:
            logger.error(f"Error logging security event for user {user_id}: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()

    def populate_mock_threat_intelligence(self, num_entries=100):
        """Populates mock threat intelligence data for demonstration."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Delete only mock data to allow for manual entries or other sources
            cursor.execute("DELETE FROM threat_intelligence WHERE source = 'Mock Data';")
            conn.commit()
            
            threat_types = ["Malware_C2", "Phishing_URL", "DDoS_Source_IP", "SQL_Injection_Attempt", "XSS_Payload", "Brute_Force_IP", "Vulnerability_Exploit"]
            sources = ["ThreatFeed-A", "OSINT_Report", "Internal_IPS", "DarkWeb_Scraper", "Mock Data", "Community_Feed"]
            
            # More varied indicators
            ip_indicators = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)] + \
                            [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)] + \
                            [f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)] + \
                            [f"203.0.113.{random.randint(1,254)}" for _ in range(10)] # Public IPs
            
            domain_indicators = [f"malicious-{secrets.token_hex(3)}.biz", f"phish-{secrets.token_hex(4)}.com", f"c2server-{secrets.token_hex(2)}.ru", f"exploit-kit.{secrets.token_hex(3)}.info"]
            
            hash_indicators = [secrets.token_hex(32) for _ in range(30)] # MD5/SHA256 mock hashes
            
            for i in range(num_entries):
                threat_type = random.choice(threat_types)
                source = random.choice(sources)
                confidence = random.randint(30, 100)
                
                indicator = ""
                if "IP" in threat_type:
                    indicator = random.choice(ip_indicators)
                elif "URL" in threat_type or "Domain" in threat_type:
                    indicator = random.choice(domain_indicators)
                elif "Hash" in threat_type or "Malware" in threat_type:
                    indicator = random.choice(hash_indicators)
                else: # Generic or other types
                    indicator = f"{threat_type.replace('_','-').lower()}-{secrets.token_hex(5)}"

                days_ago = random.randint(0, 90) # Up to 90 days old
                timestamp = datetime.now() - timedelta(days=days_ago, hours=random.randint(0,23), minutes=random.randint(0,59))

                try:
                    cursor.execute('''
                        INSERT INTO threat_intelligence
                            (timestamp, indicator, threat_type, confidence, source, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (indicator) DO UPDATE SET
                            timestamp = EXCLUDED.timestamp,
                            threat_type = EXCLUDED.threat_type,
                            confidence = EXCLUDED.confidence,
                            source = EXCLUDED.source,
                            status = EXCLUDED.status,
                            last_updated = CURRENT_TIMESTAMP;
                    ''', (timestamp, indicator, threat_type, confidence, source, 'active'))
                except psycopg2.IntegrityError:
                    conn.rollback() # Handle potential race condition if unique constraint fails
                    logger.warning(f"Duplicate threat intelligence indicator {indicator} attempted, skipping.")
                    continue # Skip to next iteration
            conn.commit()
            logger.info(f"Populated {num_entries} mock threat intelligence entries.")
        except Exception as e:
            logger.error(f"Error populating mock threat intelligence: {e}", exc_info=True)
            conn.rollback()
        finally:
            conn.close()

    @log_api_call
    def search_threat_intelligence(self, indicator=None, threat_type=None, source=None, min_confidence=None, status='active', limit=100):
        """
        Searches for threat intelligence indicators in the database.
        Allows filtering by indicator, threat_type, source, minimum confidence, and status.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT timestamp, indicator, threat_type, confidence, source, status, last_updated FROM threat_intelligence WHERE 1=1"
        params = []

        if indicator:
            query += " AND indicator ILIKE %s" # Case-insensitive search
            params.append(f'%{indicator}%')
        if threat_type:
            query += " AND threat_type = %s"
            params.append(threat_type)
        if source:
            query += " AND source = %s"
            params.append(source)
        if min_confidence is not None:
            query += " AND confidence >= %s"
            params.append(min_confidence)
        if status:
            query += " AND status = %s"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        try:
            cursor.execute(query, tuple(params))
            results = cursor.fetchall()
            
            formatted_results = []
            for row in results:
                formatted_results.append({
                    'timestamp': row[0],
                    'indicator': row[1],
                    'threat_type': row[2],
                    'confidence': row[3],
                    'source': row[4],
                    'status': row[5],
                    'last_updated': row[6]
                })
            logger.info(f"Threat intelligence search performed. Found {len(formatted_results)} results.")
            return formatted_results
        except Exception as e:
            logger.error(f"Error searching threat intelligence: {e}", exc_info=True)
            raise
        finally:
            conn.close()

    # --- Idempotency Methods for Webhooks ---
    def is_event_already_processed(self, event_id):
        """Checks if a Stripe event has already been processed using the database."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM processed_webhook_events WHERE event_id = %s", (event_id,))
            return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking event idempotency for {event_id}: {e}", exc_info=True)
            # Depending on desired behavior, you might want to re-raise or handle more gracefully.
            # Returning False here means it will attempt to process the event, which could lead to duplicates
            # if the DB is truly down. Better to assume un-processed or fail explicitly if critical.
            raise # Re-raise to ensure integrity if DB is an issue
        finally:
            if conn:
                conn.close()

    def mark_event_as_processed(self, event_id, event_type=None):
        """Marks a Stripe event as processed in the database."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO processed_webhook_events (event_id, event_type) VALUES (%s, %s)",
                (event_id, event_type)
            )
            conn.commit()
            logger.info(f"Event {event_id} marked as processed.")
        except psycopg2.IntegrityError:
            # This means the event_id already exists, it was likely processed concurrently
            logger.warning(f"Attempted to mark already processed event {event_id}.")
            conn.rollback() # Rollback the insert attempt
        except Exception as e:
            logger.error(f"Error marking event {event_id} as processed: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
