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
from typing import Dict, Any, Optional, Tuple, List, Union
import jwt
from datetime import datetime, timedelta

# Import get_db_connection, return_db_connection, and close_db_pool from the utils
from utils.database import get_db_connection, return_db_connection, close_db_pool

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurable trial duration
DEFAULT_TRIAL_DAYS = int(os.getenv('DEFAULT_TRIAL_DAYS', 30))

# --- Constants for consistency and maintainability ---
USER_ROLES = {'user', 'admin', 'guest'}
USER_STATUSES = {'active', 'inactive', 'suspended', 'pending_email_verification'}
PAYMENT_STATUSES = {'trial', 'unverified', 'active', 'past_due', 'canceled'}
ALLOWED_PLANS = {'essentials', 'basic', 'professional', 'business', 'enterprise'}
API_KEY_PERMISSIONS = {'read', 'write', 'admin'}
API_KEY_STATUSES = {'active', 'inactive'}

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
            raise # Re-raise the exception after logging
    return wrapper

class SecurityCore:
    def __init__(self):
        self.SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret")  # Load from env
        self.ALGORITHM = "HS256"
        self.TOKEN_EXPIRE_MINUTES = 60
        
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_database()    self.TOKEN_EXPIRE_MINUTES = 60

    def create_access_token(self, data: dict):
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def verify_access_token(self, token: str):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            return payload.get("id") or payload.get("sub")  # Either works
        except jwt.ExpiredSignatureError:
            return None
        except jwt.PyJWTError:
            return None
            
    def __init__(self):
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_database()

    def _sanitize_input(self, data: Optional[str], max_length: int) -> Optional[str]:
        """
        Basic sanitization for string inputs.
        Removes leading/trailing whitespace and truncates to max_length.
        For more complex cases (e.g., HTML), dedicated libraries are recommended.
        """
        if data is None:
            return None
        sanitized = str(data).strip()
        return sanitized[:max_length] if len(sanitized) > max_length else sanitized

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
            
            # Ensure 'payment_status' column exists for users
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'payment_status';
            """)
            if not cursor.fetchone():
                logger.info("Adding payment_status column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN payment_status VARCHAR(50) DEFAULT 'trial';")
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
            if conn: # Ensure rollback on error
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def get_or_create_encryption_key(self) -> Fernet:
        """
        Retrieves or generates the encryption key for API keys.
        For high-security production, consider managing this key via environment variables
        or a dedicated secrets management service.
        """
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

    def hash_password(self, password: str) -> str:
        """Hashes a password using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password: str, hash_string: str) -> bool:
        """Verifies a password against a hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_string.encode('utf-8'))
        except Exception:
            return False

    def validate_email_input(self, email: str) -> Optional[str]:
        """Validates email format using email_validator."""
        try:
            validated_email = validate_email(email)
            return validated_email.email
        except EmailNotValidError:
            return None

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validates password strength (length, uppercase, lowercase, digit)."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number."
        return True, "Password is strong."

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypts an API key."""
        return self.encryption_key.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key: str) -> Optional[str]:
        """
        Decrypts an API key.
        Returns None if decryption fails (e.g., invalid key or encryption key changed).
        """
        try:
            return self.encryption_key.decrypt(encrypted_key.encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt API key: {e}. Key might be invalid or encryption key changed.", exc_info=True)
            return None

    @log_api_call
    def promote_to_admin(self, user_id: str) -> bool:
        """Promotes a user's role to 'admin'."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET role = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, ('admin', user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for promotion.")
                return False
            logger.info(f"User {user_id} promoted to admin.")
            return True
        except Exception as e:
            logger.error(f"Error promoting user {user_id} to admin: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def demote_to_user(self, user_id: str) -> bool:
        """Demotes a user's role to 'user'."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET role = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, ('user', user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for demotion.")
                return False
            logger.info(f"User {user_id} demoted to user.")
            return True
        except Exception as e:
            logger.error(f"Error demoting user {user_id} to user: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def deactivate_user_account(self, user_id: str) -> bool:
        """Deactivates a user account (sets status to 'inactive')."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, ('inactive', user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for deactivation.")
                return False
            self.log_security_event(user_id, "user_account_deactivated", "info", f"User account {user_id} deactivated.")
            logger.info(f"User account {user_id} deactivated.")
            return True
        except Exception as e:
            logger.error(f"Error deactivating user account {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def activate_user_account(self, user_id: str) -> bool:
        """Activates a user account (sets status to 'active')."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s
            """, ('active', user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for activation.")
                return False
            self.log_security_event(user_id, "user_account_activated", "info", f"User account {user_id} activated.")
            logger.info(f"User account {user_id} activated.")
            return True
        except Exception as e:
            logger.error(f"Error activating user account {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def create_user(self, email: str, password: str, company: str, first_name: str, last_name: str, plan: str,
                    phone: str = "", job_title: str = "", billing_period: str = "monthly", email_token: Optional[str] = None,
                    email_verified: bool = False, role: str = 'user', subscription_id: Optional[str] = None,
                    auto_renewal: bool = True) -> Tuple[Optional[str], str]:
        """
        Creates a new user in the database.
        Includes initial trial setup and email verification status.

        Args:
            email (str): User's email address.
            password (str): User's raw password.
            company (str): User's company name.
            first_name (str): User's first name.
            last_name (str): User's last name.
            plan (str): Subscription plan ('essentials', 'basic', etc.).
            phone (str, optional): User's phone number. Defaults to "".
            job_title (str, optional): User's job title. Defaults to "".
            billing_period (str, optional): Billing period ('monthly' or 'yearly'). Defaults to "monthly".
            email_token (str, optional): Token for email verification. Defaults to None.
            email_verified (bool, optional): Whether email is verified. Defaults to False.
            role (str, optional): User's role ('user' or 'admin'). Defaults to 'user'.
            subscription_id (str, optional): Stripe subscription ID. Defaults to None.
            auto_renewal (bool, optional): Auto-renewal status. Defaults to True.

        Returns:
            Tuple[Optional[str], str]: A tuple containing the user ID if successful, and a message.
                                        Returns (None, error_message) on failure.
        """
        validated_email = self.validate_email_input(email)
        if not validated_email:
            return None, "Invalid email format."

        # Check if user already exists by email
        if self.get_user_by_email(validated_email):
            return None, "Email address already exists."

        # Validate password strength
        is_strong, strength_message = self.validate_password_strength(password)
        if not is_strong:
            return None, strength_message

        # Sanitize inputs
        company = self._sanitize_input(company, 255)
        first_name = self._sanitize_input(first_name, 255)
        last_name = self._sanitize_input(last_name, 255)
        phone = self._sanitize_input(phone, 50)
        job_title = self._sanitize_input(job_title, 255)

        # Validate plan and role against constants
        if plan not in ALLOWED_PLANS:
            return None, f"Invalid plan selected. Must be one of: {', '.join(ALLOWED_PLANS)}."
        if role not in USER_ROLES:
            return None, f"Invalid role selected. Must be one of: {', '.join(USER_ROLES)}."

        user_id = secrets.token_urlsafe(16)
        password_hash = self.hash_password(password)

        trial_start = datetime.now()
        trial_end = trial_start + timedelta(days=DEFAULT_TRIAL_DAYS)
        
        # Initial payment status based on email verification
        initial_payment_status = 'unverified'
        if email_verified:
            initial_payment_status = 'trial' if subscription_id is None else PAYMENT_STATUSES.get('active') # If sub_id exists, assume active

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (id, email, password_hash, company, first_name, last_name,
                                 phone, job_title, plan, trial_start_date, trial_end_date,
                                 is_trial, billing_period, auto_renewal, trial_ends,
                                 email_token, email_verified, role, subscription_id, payment_status, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (user_id, validated_email, password_hash, company, first_name, last_name,
                  phone, job_title, plan, trial_start, trial_end, True, billing_period, auto_renewal, trial_end,
                  email_token, email_verified, role, subscription_id, initial_payment_status, 'active')) # Default status active on creation
            conn.commit()
            logger.info(f"User {user_id} created successfully.")
            return user_id, "User created successfully."
        except psycopg2.IntegrityError as e:
            logger.error(f"Database integrity error in create_user: {e}", exc_info=True)
            if conn:
                conn.rollback()
            if "users_email_key" in str(e):
                return None, "Email address already exists."
            return None, "Failed to create user account due to data conflict (e.g., email already exists or invalid subscription ID)."
        except Exception as e:
            logger.error(f"Database error in create_user: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return None, f"Database error: {str(e)}"
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves full user details by email."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, password_hash, company, first_name, last_name, phone, job_title,
                       plan, role, status, trial_ends, payment_status, email_token, email_verified,
                       is_trial, subscription_id, trial_start_date, auto_renewal
                FROM users WHERE email = %s
            ''', (email,))
            result = cursor.fetchone()

            if result:
                return {
                    'id': result[0], 'email': result[1], 'password_hash': result[2],
                    'company': result[3], 'first_name': result[4], 'last_name': result[5],
                    'phone': result[6], 'job_title': result[7], 'plan': result[8],
                    'role': result[9], 'status': result[10], 'trial_ends': result[11],
                    'payment_status': result[12], 'email_token': result[13],
                    'email_verified': result[14], 'is_trial': result[15],
                    'subscription_id': result[16], 'trial_start_date': result[17],
                    'auto_renewal': result[18]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving user by email: {e}", exc_info=True)
            raise # Re-raise for caller to handle
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_details(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves select user details by ID."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT email, company, first_name, last_name, phone, job_title,
                       plan, role, status, trial_ends, payment_status, email_verified,
                       is_trial, subscription_id, trial_start_date, auto_renewal
                FROM users WHERE id = %s
            ''', (user_id,))
            result = cursor.fetchone()
            if result:
                return {
                    'email': result[0], 'company': result[1], 'first_name': result[2],
                    'last_name': result[3], 'phone': result[4], 'job_title': result[5],
                    'plan': result[6], 'role': result[7], 'status': result[8],
                    'trial_ends': result[9], 'payment_status': result[10],
                    'email_verified': result[11], 'is_trial': result[12],
                    'subscription_id': result[13], 'trial_start_date': result[14],
                    'auto_renewal': result[15]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving user details for {user_id}: {e}", exc_info=True)
            raise # Re-raise for caller to handle
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_id_by_email(self, email: str) -> Optional[str]:
        """Retrieves user ID by email."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error retrieving user ID by email {email}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_id_by_subscription_id(self, subscription_id: str) -> Optional[str]:
        """Retrieves user ID by Stripe subscription ID."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE subscription_id = %s", (subscription_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error retrieving user ID by subscription ID {subscription_id}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def verify_user_email(self, user_id: str) -> bool:
        """Marks a user's email as verified and updates payment_status to 'trial' if no subscription."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            # If subscription_id is NULL, set payment_status to 'trial', otherwise keep current or set 'active'
            cursor.execute('''
                UPDATE users SET email_verified = TRUE, email_token = NULL,
                payment_status = CASE WHEN subscription_id IS NULL THEN %s ELSE payment_status END,
                updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', ('trial', user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for email verification.")
                return False
            logger.info(f"Email verified for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error verifying user email {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def authenticate_user(self, email: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Authenticates a user by email and password.
        Returns user info (id, role, status) and None on success, or None and error message on failure.
        """
        user = self.get_user_by_email(email)
        if not user:
            return None, "Invalid email or password."

        if not self.verify_password(password, user['password_hash']):
            # Log failed attempt without revealing if email exists
            self.log_security_event(user['id'], "login_failed", "warning",
                                    f"Failed login attempt for user {user['id']} (email: {email})",
                                    source_ip="N/A", metadata={'email': email}) # Source IP should come from request context
            return None, "Invalid email or password."

        if not user['email_verified']:
            return None, "Email not verified. Please check your inbox for the verification link."

        if user['status'] == 'inactive':
            return None, "Your account is inactive. Please contact support."
        
        if user['status'] == 'suspended':
            return None, "Your account is suspended. Please contact support."


        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', (datetime.now(), user['id']))
            conn.commit()
            logger.info(f"User {user['id']} authenticated successfully.")
            self.log_security_event(user['id'], "login_success", "info", f"User {user['id']} logged in successfully.")
        except Exception as e:
            logger.error(f"Error updating last login for user {user['id']}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            # Authentication succeeded, but updating last_login failed. Still return user info.
            logger.warning(f"Could not update last login for user {user['id']} after successful authentication.")
        finally:
            if conn:
                return_db_connection(conn)
            
        return {'id': user['id'], 'role': user['role'], 'status': user['status'], 'email_verified': user['email_verified']}, None

    def update_user_subscription_status(self, user_id: str, payment_status: str, is_trial: Optional[bool] = None,
                                        subscription_id: Optional[str] = None, trial_ends: Optional[datetime] = None,
                                        auto_renewal: Optional[bool] = None, plan: Optional[str] = None) -> bool:
        """
        Updates a user's payment, trial status, and subscription details based on webhook events.
        'trial_ends' will store the next billing date for paying customers.

        Args:
            user_id (str): The ID of the user to update.
            payment_status (str): The new payment status (e.g., 'active', 'past_due', 'canceled').
            is_trial (Optional[bool]): True if the user is in a trial, False otherwise.
            subscription_id (Optional[str]): The Stripe subscription ID.
            trial_ends (Optional[datetime]): The end date of the trial or next billing date.
            auto_renewal (Optional[bool]): Auto-renewal status.
            plan (Optional[str]): The new plan name.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        if payment_status not in PAYMENT_STATUSES:
            logger.error(f"Invalid payment status '{payment_status}' provided for user {user_id}.")
            return False
        
        if plan is not None and plan not in ALLOWED_PLANS:
            logger.error(f"Invalid plan '{plan}' provided for user {user_id}.")
            return False

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            update_fields = []
            params = []

            update_fields.append("payment_status = %s")
            params.append(payment_status)

            if is_trial is not None:
                update_fields.append("is_trial = %s")
                params.append(is_trial)
            
            # subscription_id should always be updated, even to NULL if a subscription is cancelled
            update_fields.append("subscription_id = %s")
            params.append(subscription_id)
            
            if trial_ends is not None:
                update_fields.append("trial_ends = %s")
                params.append(trial_ends)

            if auto_renewal is not None:
                update_fields.append("auto_renewal = %s")
                params.append(auto_renewal)
            
            if plan is not None:
                update_fields.append("plan = %s")
                params.append(plan)

            update_fields.append("updated_at = CURRENT_TIMESTAMP")

            update_sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
            params.append(user_id)

            cursor.execute(update_sql, tuple(params))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"User {user_id} not found for subscription status update.")
                return False
            logger.info(f"User {user_id} subscription status updated to {payment_status}. is_trial: {is_trial}, sub_id: {subscription_id}, plan: {plan}")
            return True
        except Exception as e:
            logger.error(f"Error updating user {user_id} subscription status: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def get_trial_discount_eligibility(self, user_id: str) -> bool:
        """Checks if a user is eligible for a trial conversion discount (within first 15 days of trial)."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT trial_start_date, is_trial FROM users WHERE id = %s', (user_id,))
            result = cursor.fetchone()
            if not result or not result[1]: # Not found or not currently on trial
                return False
            trial_start = result[0]
            days_since_trial = (datetime.now() - trial_start).days
            return days_since_trial <= 15 # Eligibility within first 15 days of trial
        except Exception as e:
            logger.error(f"Error checking trial discount eligibility for user {user_id}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def calculate_discounted_price(self, base_price: float, plan_name: str, billing_period: str = "monthly", user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates pricing with potential discounts based on plan, billing period, and user eligibility.

        Args:
            base_price (float): The base monthly price of the plan before any discounts.
            plan_name (str): The name of the plan (e.g., 'basic', 'professional').
            billing_period (str, optional): The billing cycle ('monthly' or 'yearly'). Defaults to "monthly".
            user_id (Optional[str], optional): The ID of the user for specific discounts. Defaults to None.

        Returns:
            Dict[str, Any]: A dictionary containing calculated prices, total savings, and a list of applied discounts.
        """
        discounts: List[str] = []
        final_monthly_base = base_price
        total_savings = 0.0

        user_info = None
        if user_id:
            user_info = self.get_user_details(user_id) # Fetch user info to check auto_renewal

        # Auto-renewal discount conditional on user's auto_renewal setting
        # This implies a $10 discount on the base monthly price if auto-renewal is true.
        if user_info and user_info.get('auto_renewal', False) and billing_period == "monthly":
            auto_renewal_discount = 10.0 # Example fixed discount
            final_monthly_base -= auto_renewal_discount
            discounts.append(f"${auto_renewal_discount:.0f} auto-renewal savings (applied monthly).")
            # Note: For total_savings for monthly, this discount would apply each month.
            # For this calculation, we'll just show the immediate impact on the monthly rate.

        monthly_price_after_auto_renewal_discount = final_monthly_base

        yearly_price = None

        if billing_period == "yearly":
            # Example: Yearly price is 10 months of the (potentially auto-renewal discounted) monthly price
            yearly_price = monthly_price_after_auto_renewal_discount * 10
            yearly_savings_amount_from_monthly = (base_price * 12) - (monthly_price_after_auto_renewal_discount * 10)
            if yearly_savings_amount_from_monthly > 0:
                discounts.append(f"Yearly subscription savings (approx. 2 months FREE, save ${yearly_savings_amount_from_monthly:.0f}/year).")
                total_savings += yearly_savings_amount_from_monthly # This is annual savings

            if user_id and self.get_trial_discount_eligibility(user_id):
                trial_discount_percentage = 0.25 # 25% off yearly price
                trial_discount_amount = yearly_price * trial_discount_percentage
                yearly_price -= trial_discount_amount
                discounts.append(f"{trial_discount_percentage*100:.0f}% trial conversion discount (save ${trial_discount_amount:.0f} on first year).")
                total_savings += trial_discount_amount

            return {
                'monthly_base_rate': base_price, # Original base rate for context
                'monthly_rate_after_auto_renewal': monthly_price_after_auto_renewal_discount,
                'yearly_price_billed': yearly_price,
                'total_yearly_savings': total_savings,
                'discounts_applied': discounts,
                'billing_period': billing_period
            }

        # Monthly billing period specific discounts
        monthly_price_billed = monthly_price_after_auto_renewal_discount
        if user_id and self.get_trial_discount_eligibility(user_id):
            # Apply 25% off for the first 3 months on monthly price.
            # This logic assumes the 'monthly_price' returned reflects the immediate charge.
            # If the discount is for future months, the UI would need to reflect that.
            trial_discount_percentage = 0.25
            trial_discount_per_month = monthly_price_after_auto_renewal_discount * trial_discount_percentage
            trial_savings_over_3_months = trial_discount_per_month * 3
            discounts.append(f"{trial_discount_percentage*100:.0f}% off first 3 months (save ${trial_savings_over_3_months:.0f} total).")
            total_savings += trial_savings_over_3_months
            
            # If you want to return the *discounted* monthly price for the first 3 months as the current rate,
            # you would uncomment the following:
            # monthly_price_billed = monthly_price_after_auto_renewal_discount - trial_discount_per_month


        return {
            'monthly_base_rate': base_price,
            'monthly_rate_after_auto_renewal': monthly_price_after_auto_renewal_discount,
            'monthly_price_billed': monthly_price_billed, # This is the price charged per month (may or may not include the first 3 months discount implicitly)
            'total_monthly_savings_over_3_months': total_savings, # Represents total savings over a specific period for monthly
            'discounts_applied': discounts,
            'billing_period': billing_period
        }

    @log_api_call
    def add_api_key(self, user_id: str, name: str, api_key: str, service: str, permissions: str = "read") -> Optional[str]:
        """
        Adds an encrypted API key for a user.

        Args:
            user_id (str): The ID of the user.
            name (str): A human-readable name for the API key.
            api_key (str): The actual raw API key.
            service (str): The service this API key is for (e.g., 'stripe', 'openai').
            permissions (str, optional): The permissions associated with the key (e.g., 'read', 'write'). Defaults to "read".

        Returns:
            Optional[str]: The generated key ID if successful, None otherwise.
        """
        if permissions not in API_KEY_PERMISSIONS:
            logger.error(f"Invalid permissions '{permissions}' provided for API key '{name}'.")
            return None
        
        name = self._sanitize_input(name, 255)
        service = self._sanitize_input(service, 255)

        key_id = secrets.token_urlsafe(16)
        encrypted_key = self.encrypt_api_key(api_key)
        if encrypted_key is None: # Should not happen unless encryption key is bad
            logger.error("Failed to encrypt API key, cannot add to database.")
            return None

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
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
            if conn:
                conn.rollback()
            return None # Return None on failure
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def update_api_key_last_used(self, key_id: str) -> bool:
        """Updates the last_used timestamp for an API key."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
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
            if conn:
                conn.rollback()
            raise # Re-raise for caller to handle
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def get_api_key(self, key_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific API key for a user (encrypted)."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, encrypted_key, service, permissions, created_at, last_used, status
                FROM api_keys WHERE id = %s AND user_id = %s
            """, (key_id, user_id))
            result = cursor.fetchone()
            if result:
                return {
                    'id': result[0],
                    'name': result[1],
                    'encrypted_key': result[2], # Return encrypted key, decryption happens externally if needed
                    'service': result[3],
                    'permissions': result[4],
                    'created_at': result[5],
                    'last_used': result[6],
                    'status': result[7]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving API key {key_id} for user {user_id}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """Lists all API keys (encrypted) for a given user."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, encrypted_key, service, permissions, created_at, last_used, status
                FROM api_keys WHERE user_id = %s
            """, (user_id,))
            results = cursor.fetchall()
            keys = []
            for result in results:
                keys.append({
                    'id': result[0],
                    'name': result[1],
                    'encrypted_key': result[2],
                    'service': result[3],
                    'permissions': result[4],
                    'created_at': result[5],
                    'last_used': result[6],
                    'status': result[7]
                })
            return keys
        except Exception as e:
            logger.error(f"Error listing API keys for user {user_id}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def delete_api_key(self, key_id: str, user_id: str) -> bool:
        """Deletes an API key for a user."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM api_keys WHERE id = %s AND user_id = %s
            """, (key_id, user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"API key {key_id} not found or does not belong to user {user_id} for deletion.")
                return False
            self.log_security_event(user_id, "api_key_deleted", "info", f"API key {key_id} deleted.")
            logger.info(f"API key {key_id} deleted for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error deleting API key {key_id} for user {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def deactivate_api_key(self, key_id: str, user_id: str) -> bool:
        """Deactivates an API key for a user (soft-deletion)."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys SET status = %s, last_used = %s WHERE id = %s AND user_id = %s
            """, ('inactive', datetime.now(), key_id, user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"API key {key_id} not found or does not belong to user {user_id} for deactivation.")
                return False
            self.log_security_event(user_id, "api_key_deactivated", "info", f"API key {key_id} deactivated.")
            logger.info(f"API key {key_id} deactivated for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error deactivating API key {key_id} for user {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def activate_api_key(self, key_id: str, user_id: str) -> bool:
        """Activates a previously deactivated API key for a user."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys SET status = %s WHERE id = %s AND user_id = %s
            """, ('active', key_id, user_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"API key {key_id} not found or does not belong to user {user_id} for activation.")
                return False
            self.log_security_event(user_id, "api_key_activated", "info", f"API key {key_id} activated.")
            logger.info(f"API key {key_id} activated for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error activating API key {key_id} for user {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def log_security_event(self, user_id: str, event_type: str, severity: str, description: str, source_ip: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Logs a security event to the database.

        Args:
            user_id (str): The ID of the user associated with the event.
            event_type (str): The type of event (e.g., 'login_failed', 'api_key_deleted').
            severity (str): The severity level (e.g., 'info', 'warning', 'critical').
            description (str): A brief description of the event.
            source_ip (Optional[str]): The IP address from which the event originated. Defaults to None.
            metadata (Optional[Dict[str, Any]]): Additional JSONB data for the event. Defaults to None.

        Returns:
            bool: True if the event was logged successfully, False otherwise.
        """
        event_id = secrets.token_urlsafe(16)
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (id, user_id, event_type, severity, description, source_ip, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (event_id, user_id, event_type, severity, description, source_ip, json.dumps(metadata) if metadata else None))
            conn.commit()
            logger.debug(f"Security event '{event_type}' logged for user {user_id}.")
            return True
        except Exception as e:
            logger.error(f"Error logging security event for user {user_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def get_security_events(self, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieves a list of security events for a specific user."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, event_type, severity, description, source_ip, metadata, timestamp, resolved
                FROM security_events WHERE user_id = %s
                ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """, (user_id, limit, offset))
            results = cursor.fetchall()
            events = []
            for result in results:
                events.append({
                    'id': result[0],
                    'event_type': result[1],
                    'severity': result[2],
                    'description': result[3],
                    'source_ip': result[4],
                    'metadata': result[5],
                    'timestamp': result[6],
                    'resolved': result[7]
                })
            return events
        except Exception as e:
            logger.error(f"Error retrieving security events for user {user_id}: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def update_security_event_status(self, event_id: str, resolved: bool) -> bool:
        """Updates the resolution status of a security event."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE security_events SET resolved = %s WHERE id = %s
            """, (resolved, event_id))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"Security event {event_id} not found for status update.")
                return False
            logger.info(f"Security event {event_id} resolved status set to {resolved}.")
            return True
        except Exception as e:
            logger.error(f"Error updating security event {event_id} status: {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def add_threat_intelligence_indicator(self, indicator: str, threat_type: str, confidence: int, source: str, status: str = 'active') -> bool:
        """
        Adds a new threat intelligence indicator to the database.
        Prevents duplicates based on the 'indicator' column due to UNIQUE constraint.
        """
        if status not in ['active', 'inactive', 'deprecated']: # Example statuses
            logger.error(f"Invalid status '{status}' provided for threat intelligence indicator.")
            return False

        indicator = self._sanitize_input(indicator, 255)
        threat_type = self._sanitize_input(threat_type, 100)
        source = self._sanitize_input(source, 100)

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_intelligence (indicator, threat_type, confidence, source, status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (indicator) DO UPDATE SET
                    threat_type = EXCLUDED.threat_type,
                    confidence = EXCLUDED.confidence,
                    source = EXCLUDED.source,
                    status = EXCLUDED.status,
                    last_updated = CURRENT_TIMESTAMP
            ''', (indicator, threat_type, confidence, source, status))
            conn.commit()
            logger.info(f"Threat intelligence indicator '{indicator}' added/updated successfully.")
            return True
        except Exception as e:
            logger.error(f"Error adding/updating threat intelligence indicator '{indicator}': {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def get_threat_intelligence_indicator(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific threat intelligence indicator."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, indicator, threat_type, confidence, source, status, last_updated
                FROM threat_intelligence WHERE indicator = %s
            """, (indicator,))
            result = cursor.fetchone()
            if result:
                return {
                    'id': result[0],
                    'timestamp': result[1],
                    'indicator': result[2],
                    'threat_type': result[3],
                    'confidence': result[4],
                    'source': result[5],
                    'status': result[6],
                    'last_updated': result[7]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving threat intelligence indicator '{indicator}': {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def delete_threat_intelligence_indicator(self, indicator: str) -> bool:
        """Deletes a threat intelligence indicator."""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM threat_intelligence WHERE indicator = %s
            """, (indicator,))
            conn.commit()
            if cursor.rowcount == 0:
                logger.warning(f"Threat intelligence indicator '{indicator}' not found for deletion.")
                return False
            logger.info(f"Threat intelligence indicator '{indicator}' deleted.")
            return True
        except Exception as e:
            logger.error(f"Error deleting threat intelligence indicator '{indicator}': {e}", exc_info=True)
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def is_event_already_processed(self, event_id: str, event_type: str) -> bool:
        """
        Checks if a webhook event has already been processed to ensure idempotency.
        
        Args:
            event_id (str): Unique ID of the event from the webhook source.
            event_type (str): Type of the event (e.g., 'customer.subscription.updated').
            
        Returns:
            bool: True if the event has been processed, False otherwise.
        """
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT EXISTS (SELECT 1 FROM processed_webhook_events WHERE event_id = %s)
            ''', (event_id,))
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error checking if event {event_id} was already processed: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    @log_api_call
    def mark_event_as_processed(self, event_id: str, event_type: str) -> bool:
        """
        Marks a webhook event as processed.
        
        Args:
            event_id (str): Unique ID of the event from the webhook source.
            event_type (str): Type of the event (e.g., 'customer.subscription.updated').
            
        Returns:
            bool: True if the event was marked as processed, False otherwise.
        """
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO processed_webhook_events (event_id, event_type)
                VALUES (%s, %s)
                ON CONFLICT (event_id) DO NOTHING
            ''', (event_id, event_type))
            conn.commit()
            # If rowcount is 0, it means an existing row conflicted (event was already processed)
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error marking event {event_id} as processed: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                return_db_connection(conn)

# --- Application Startup/Shutdown Hook Example ---
# In your main application file (e.g., app.py or main.py), you would:
# from utils.database import init_db_pool, close_db_pool

# On application start:
# init_db_pool()
# security_core_instance = SecurityCore() # This will call init_database()

# On application shutdown:
# close_db_pool() # Important!

# Example of how to use it (for testing purposes, in a real app this would be in routes/controllers)
if __name__ == '__main__':
    # Initialize the database pool (done once at app startup)
    try:
        from utils.database import init_db_pool, close_db_pool
        init_db_pool()
    except Exception as e:
        logger.critical(f"Failed to initialize database pool on startup: {e}")
        exit(1) # Exit if database cannot be initialized

    security_core = SecurityCore()

    print("\n--- Testing User Creation and Authentication ---")
    test_email = f"test_user_{secrets.token_hex(4)}@example.com"
    test_password = "SecurePassword123!"
    user_id, msg = security_core.create_user(
        email=test_email,
        password=test_password,
        company="TestCo",
        first_name="John",
        last_name="Doe",
        plan="essentials",
        email_verified=False # Start as unverified for testing verification flow
    )
    if user_id:
        print(f"User created: {user_id}, message: {msg}")
        
        print(f"\nAttempting to log in as {test_email} (unverified)...")
        authenticated_user, auth_error = security_core.authenticate_user(test_email, test_password)
        if authenticated_user:
            print(f"Authentication success! User: {authenticated_user}")
        else:
            print(f"Authentication failed: {auth_error}")
            
        print(f"\nVerifying email for user {user_id}...")
        if security_core.verify_user_email(user_id):
            print("Email verified successfully.")
            
            print(f"\nAttempting to log in as {test_email} (verified)...")
            authenticated_user, auth_error = security_core.authenticate_user(test_email, test_password)
            if authenticated_user:
                print(f"Authentication success! User: {authenticated_user}")
            else:
                print(f"Authentication failed: {auth_error}")

            print(f"\nPromoting user {user_id} to admin...")
            if security_core.promote_to_admin(user_id):
                print(f"User {user_id} is now an admin.")
            else:
                print("Failed to promote user.")

            print(f"\nDeactivating user {user_id} account...")
            if security_core.deactivate_user_account(user_id):
                print(f"User {user_id} account deactivated.")
            else:
                print("Failed to deactivate user account.")
            
            print(f"\nAttempting to log in as {test_email} (deactivated)...")
            authenticated_user, auth_error = security_core.authenticate_user(test_email, test_password)
            if authenticated_user:
                print(f"Authentication success! User: {authenticated_user}")
            else:
                print(f"Authentication failed: {auth_error}")

            print(f"\nActivating user {user_id} account...")
            if security_core.activate_user_account(user_id):
                print(f"User {user_id} account activated.")
            else:
                print("Failed to activate user account.")

        else:
            print("Email verification failed.")
    else:
        print(f"Failed to create user: {msg}")

    print("\n--- Testing API Key Management ---")
    if user_id:
        api_key_value = "sk_test_12345ABC"
        key_id = security_core.add_api_key(user_id, "My Test Key", api_key_value, "TestService", permissions="write")
        if key_id:
            print(f"API Key added with ID: {key_id}")
            encrypted_key_data = security_core.get_api_key(key_id, user_id)
            if encrypted_key_data:
                decrypted_key = security_core.decrypt_api_key(encrypted_key_data['encrypted_key'])
                print(f"Retrieved and decrypted API Key: {decrypted_key}")
                security_core.update_api_key_last_used(key_id)
                
                print(f"\nDeactivating API key {key_id}...")
                if security_core.deactivate_api_key(key_id, user_id):
                    print(f"API key {key_id} deactivated.")
                    # Verify status
                    key_info = security_core.get_api_key(key_id, user_id)
                    print(f"API key status after deactivation: {key_info['status']}")

                    print(f"\nActivating API key {key_id}...")
                    if security_core.activate_api_key(key_id, user_id):
                        print(f"API key {key_id} activated.")
                        key_info = security_core.get_api_key(key_id, user_id)
                        print(f"API key status after activation: {key_info['status']}")
                else:
                    print("Failed to deactivate/activate API key.")

                if security_core.delete_api_key(key_id, user_id):
                    print(f"API Key {key_id} deleted successfully.")
                else:
                    print(f"Failed to delete API Key {key_id}.")
            else:
                print("Failed to retrieve API key.")
        else:
            print("Failed to add API Key.")

    print("\n--- Testing Threat Intelligence ---")
    indicator1 = "192.168.1.1"
    indicator2 = "malicious.com"
    if security_core.add_threat_intelligence_indicator(indicator1, "IP Address", 80, "OSINT"):
        print(f"Added/Updated indicator: {indicator1}")
    if security_core.add_threat_intelligence_indicator(indicator2, "Domain", 90, "InternalFeed"):
        print(f"Added/Updated indicator: {indicator2}")

    retrieved_indicator = security_core.get_threat_intelligence_indicator(indicator1)
    if retrieved_indicator:
        print(f"Retrieved indicator {indicator1}: {retrieved_indicator}")
    
    if security_core.delete_threat_intelligence_indicator(indicator1):
        print(f"Deleted indicator: {indicator1}")


    print("\n--- Testing Webhook Idempotency ---")
    event_id_1 = "stripe_evt_123"
    event_type_1 = "invoice.payment_succeeded"
    event_id_2 = "stripe_evt_456"
    event_type_2 = "customer.created"

    print(f"Processing event {event_id_1}...")
    if not security_core.is_event_already_processed(event_id_1, event_type_1):
        if security_core.mark_event_as_processed(event_id_1, event_type_1):
            print(f"Event {event_id_1} processed successfully.")
        else:
            print(f"Failed to mark event {event_id_1} as processed.")
    else:
        print(f"Event {event_id_1} already processed.")

    print(f"Processing event {event_id_1} again (should be skipped)...")
    if not security_core.is_event_already_processed(event_id_1, event_type_1):
        if security_core.mark_event_as_processed(event_id_1, event_type_1):
            print(f"Event {event_id_1} processed successfully (THIS SHOULD NOT PRINT).")
        else:
            print(f"Failed to mark event {event_id_1} as processed (THIS SHOULD NOT PRINT).")
    else:
        print(f"Event {event_id_1} already processed (correctly skipped).")
        
    print(f"\n--- Testing Price Calculation ---")
    print("\nMonthly Plan for New User (eligible for trial discount)")
    monthly_price_new_user = security_core.calculate_discounted_price(100.0, "basic", "monthly", user_id=user_id)
    print(json.dumps(monthly_price_new_user, indent=2))

    print("\nYearly Plan for Existing User (auto-renewal ON, not trial eligible)")
    # Temporarily set user's auto_renewal to True and is_trial to False for this test
    # In a real scenario, this would reflect actual user data
    security_core.update_user_subscription_status(user_id, "active", is_trial=False, auto_renewal=True)
    yearly_price_existing_user = security_core.calculate_discounted_price(100.0, "professional", "yearly", user_id=user_id)
    print(json.dumps(yearly_price_existing_user, indent=2))

    print("\nMonthly Plan for Existing User (auto-renewal OFF, not trial eligible)")
    security_core.update_user_subscription_status(user_id, "active", is_trial=False, auto_renewal=False)
    monthly_price_existing_user_no_renewal = security_core.calculate_discounted_price(100.0, "basic", "monthly", user_id=user_id)
    print(json.dumps(monthly_price_existing_user_no_renewal, indent=2))

    # Clean up user and key for re-runs
    if user_id:
        try:
            print(f"\nCleaning up test user {user_id}...")
            # Deactivate to ensure it's in a known state before deletion (if you had hard delete policy)
            security_core.deactivate_user_account(user_id)
            # PostgreSQL CASCADE will delete API keys and security events automatically
            conn_cleanup = get_db_connection()
            cursor_cleanup = conn_cleanup.cursor()
            cursor_cleanup.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn_cleanup.commit()
            return_db_connection(conn_cleanup)
            print(f"Test user {user_id} and associated data deleted.")
        except Exception as e:
            logger.error(f"Error during test user cleanup: {e}", exc_info=True)

    # Close the database pool (done once at app shutdown)
    close_db_pool()
    print("\nDatabase pool closed. Script finished.")
