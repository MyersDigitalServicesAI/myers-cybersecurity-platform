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
import psycopg2
from typing import Dict, Any, Optional, Tuple, List, Union
import jwt

# Import get_db_connection, return_db_connection, and close_db_pool from the utils
# This import assumes 'utils' is a package (has __init__.py) and 'database.py' is inside it.
from utils.database import get_db_connection, return_db_connection, close_db_pool

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
            logger.info(f"API Call: {func.__name__} executed successfully.")
            return result
        except Exception as e:
            logger.error(f"API Call: {func.__name__} failed with error: {e}", exc_info=True)
            raise
    return wrapper

class SecurityCore:
    def __init__(self):
        """
        Initializes the SecurityCore with JWT secret, algorithm, token expiration,
        encryption key, and database connection.
        """
        self.SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
        if not self.SECRET_KEY:
            logger.critical("JWT_SECRET_KEY environment variable not set. JWT operations will fail.")
            raise ValueError("JWT_SECRET_KEY environment variable is required.")
        self.ALGORITHM = "HS256"
        self.TOKEN_EXPIRE_MINUTES = 60
        
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_database()

    def get_or_create_encryption_key(self):
        """
        Retrieves the encryption key from an environment variable or generates a new one.
        In a production environment, this should ideally be managed by a dedicated secrets manager.
        """
        key = os.getenv("ENCRYPTION_KEY")
        if key:
            logger.info("Using encryption key from environment variable.")
            return key.encode('utf-8')
        else:
            logger.warning("ENCRYPTION_KEY environment variable not found. Generating a new key.")
            # Generate a new key and store it in an environment variable for persistent use
            # This is for demonstration; in production, use a secure secrets management system.
            key = Fernet.generate_key().decode('utf-8')
            os.environ["ENCRYPTION_KEY"] = key # Set for current process, not persistent across restarts
            return key.encode('utf-8')

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypts an API key using Fernet symmetric encryption."""
        f = Fernet(self.encryption_key)
        return f.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_api_key: str) -> Optional[str]:
        """Decrypts an API key using Fernet symmetric encryption."""
        f = Fernet(self.encryption_key)
        try:
            return f.decrypt(encrypted_api_key.encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt API key: {e}", exc_info=True)
            return None

    def init_database(self):
        """
        Initializes the PostgreSQL database, creating necessary tables if they don't exist.
        This includes tables for users, API keys, security events, and threat intelligence.
        """
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Create 'users' table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    company_name VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'user' NOT NULL,
                    status VARCHAR(50) DEFAULT 'pending_email_verification' NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    email_verified BOOLEAN DEFAULT FALSE,
                    verification_token VARCHAR(255),
                    password_reset_token VARCHAR(255),
                    password_reset_expires TIMESTAMP,
                    plan VARCHAR(50) DEFAULT 'essentials',
                    subscription_status VARCHAR(50) DEFAULT 'unverified',
                    trial_start_date TIMESTAMP,
                    trial_end_date TIMESTAMP,
                    auto_renewal BOOLEAN DEFAULT TRUE,
                    stripe_customer_id VARCHAR(255), -- Added for Stripe customer ID
                    stripe_subscription_id VARCHAR(255) -- Added for Stripe subscription ID
                );
            """)
            logger.info("Table 'users' ensured.")

            # Create 'api_keys' table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    key_hash VARCHAR(255) UNIQUE NOT NULL,
                    encrypted_key_value TEXT NOT NULL,
                    name VARCHAR(255),
                    permissions JSONB DEFAULT '[]'::jsonb,
                    status VARCHAR(50) DEFAULT 'active' NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP
                );
            """)
            logger.info("Table 'api_keys' ensured.")

            # Create 'security_events' table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    event_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    description TEXT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            logger.info("Table 'security_events' ensured.")

            # Create 'threat_intelligence' table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    indicator VARCHAR(255) NOT NULL,
                    threat_type VARCHAR(100) NOT NULL,
                    confidence INTEGER NOT NULL,
                    source VARCHAR(100),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'active'
                );
            """)
            logger.info("Table 'threat_intelligence' ensured.")

            # Add unique constraint to threat_intelligence.indicator if it doesn't exist
            try:
                cursor.execute("""
                    ALTER TABLE threat_intelligence
                    ADD CONSTRAINT unique_indicator UNIQUE (indicator);
                """)
                logger.info("Unique constraint 'unique_indicator' added to 'threat_intelligence'.")
            except psycopg2.errors.DuplicateObject:
                logger.info("Unique constraint 'unique_indicator' already exists on 'threat_intelligence'.")
            except Exception as e:
                logger.error(f"Error adding unique constraint to threat_intelligence: {e}", exc_info=True)

            # Add event_id and event_type to security_events for webhook idempotency
            try:
                cursor.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_id VARCHAR(255);")
                cursor.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_source VARCHAR(100);")
                conn.commit()
                logger.info("Columns 'event_id' and 'event_source' ensured in 'security_events'.")
            except Exception as e:
                logger.error(f"Error adding event_id/event_source to security_events: {e}", exc_info=True)

            conn.commit()
            logger.info("Database initialization complete.")

        except psycopg2.Error as e:
            logger.critical(f"Database initialization failed: {e}", exc_info=True)
            raise
        except Exception as e:
            logger.critical(f"An unexpected error occurred during database initialization: {e}", exc_info=True)
            raise
        finally:
            if conn:
                return_db_connection(conn)

    def _sanitize_input(self, text: str) -> str:
        """Basic sanitization to prevent common injection attacks."""
        if not isinstance(text, str):
            return ""
        # Remove leading/trailing whitespace
        text = text.strip()
        # Basic HTML entity escaping (for display, not for SQL)
        text = text.replace("<", "&lt;").replace(">", "&gt;")
        # Remove common script tags, though parameterized queries are the main defense
        text = re.sub(r'<\s*script.*?>.*?<\s*/\s*script.*?>', '', text, flags=re.IGNORECASE | re.DOTALL)
        return text

    def hash_password(self, password: str) -> str:
        """Hashes a password using bcrypt."""
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')

    def check_password(self, password: str, hashed_password: str) -> bool:
        """Checks a password against a bcrypt hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def validate_email_input(self, email: str) -> bool:
        """Validates an email address format."""
        try:
            v = validate_email(email)
            return True
        except EmailNotValidError as e:
            logger.warning(f"Invalid email format for {email}: {e}")
            return False

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validates password strength.
        Requires at least 8 characters, one uppercase, one lowercase, one digit, one special character.
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, "Password is strong enough."

    def generate_api_key(self) -> str:
        """Generates a cryptographically secure API key."""
        return secrets.token_urlsafe(32)

    def hash_api_key(self, api_key: str) -> str:
        """Hashes an API key for storage."""
        return bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def create_access_token(self, user_id: str, user_role: str, expires_delta: Optional[timedelta] = None) -> str:
        """Creates a JWT access token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.TOKEN_EXPIRE_MINUTES)
        to_encode = {"exp": expire, "sub": str(user_id), "role": user_role}
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def verify_access_token(self, token: str) -> Optional[str]:
        """Verifies a JWT access token and returns the user ID if valid."""
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            # Use 'sub' as the standard claim for subject (user ID)
            user_id = payload.get("sub")
            if user_id:
                return user_id
            else:
                logger.warning("JWT token payload missing 'sub' claim.")
                return None
        except jwt.ExpiredSignatureError:
            logger.warning("Expired JWT token.")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token.")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying access token: {e}", exc_info=True)
            return None

    def create_user(self, email: str, password: str, first_name: str, last_name: str, company_name: str, role: str = 'user', plan: str = 'essentials', is_trial_eligible: bool = True) -> Tuple[Optional[str], str]:
        """
        Creates a new user in the database.
        Returns (user_id, message).
        """
        if not self.validate_email_input(email):
            return None, "Invalid email format."
        
        is_strong, msg = self.validate_password_strength(password)
        if not is_strong:
            return None, msg

        hashed_password = self.hash_password(password)
        sanitized_email = self._sanitize_input(email)
        sanitized_first_name = self._sanitize_input(first_name)
        sanitized_last_name = self._sanitize_input(last_name)
        sanitized_company_name = self._sanitize_input(company_name)

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Generate a verification token
            verification_token = secrets.token_urlsafe(32)

            # Determine trial period
            trial_start = datetime.utcnow() if is_trial_eligible else None
            trial_end = (datetime.utcnow() + timedelta(days=DEFAULT_TRIAL_DAYS)) if is_trial_eligible else None
            subscription_status = 'trial' if is_trial_eligible else 'unverified'

            cursor.execute(
                """
                INSERT INTO users (email, password_hash, first_name, last_name, company_name, role, status, verification_token, plan, subscription_status, trial_start_date, trial_end_date)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending_email_verification', %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (sanitized_email, hashed_password, sanitized_first_name, sanitized_last_name, sanitized_company_name, role, verification_token, plan, subscription_status, trial_start, trial_end)
            )
            user_id = cursor.fetchone()[0]
            conn.commit()
            logger.info(f"User {user_id} created successfully with email {sanitized_email}.")
            return str(user_id), "User created successfully. Please verify your email."
        except psycopg2.errors.UniqueViolation:
            logger.warning(f"Attempt to create user with existing email: {sanitized_email}")
            return None, "Email already registered."
        except psycopg2.Error as e:
            logger.error(f"Database error creating user: {e}", exc_info=True)
            return None, "Database error during user creation."
        except Exception as e:
            logger.error(f"Unexpected error creating user: {e}", exc_info=True)
            return None, "An unexpected error occurred during user creation."
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves user details by email."""
        sanitized_email = self._sanitize_input(email)
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, password_hash, role, status, email_verified, first_name, last_name, company_name, plan, subscription_status, trial_start_date, trial_end_date, auto_renewal, stripe_customer_id, stripe_subscription_id FROM users WHERE email = %s;", (sanitized_email,))
            user_data = cursor.fetchone()
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                user_dict = dict(zip(columns, user_data))
                # Convert UUID to string for consistency
                user_dict['id'] = str(user_dict['id'])
                return user_dict
            return None
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving user by email: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by email: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves user details by user ID."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, password_hash, role, status, email_verified, first_name, last_name, company_name, plan, subscription_status, trial_start_date, trial_end_date, auto_renewal, stripe_customer_id, stripe_subscription_id FROM users WHERE id = %s;", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                user_dict = dict(zip(columns, user_data))
                user_dict['id'] = str(user_dict['id']) # Ensure ID is string
                return user_dict
            return None
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving user by ID: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by ID: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_by_stripe_customer_id(self, stripe_customer_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves user details by Stripe Customer ID."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, role, status, stripe_subscription_id FROM users WHERE stripe_customer_id = %s;", (stripe_customer_id,))
            user_data = cursor.fetchone()
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                user_dict = dict(zip(columns, user_data))
                user_dict['id'] = str(user_dict['id'])
                return user_dict
            return None
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving user by Stripe Customer ID: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by Stripe Customer ID: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def get_user_by_subscription_id(self, stripe_subscription_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves user details by Stripe subscription ID."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, role, status, stripe_customer_id FROM users WHERE stripe_subscription_id = %s;", (stripe_subscription_id,))
            user_data = cursor.fetchone()
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                user_dict = dict(zip(columns, user_data))
                user_dict['id'] = str(user_dict['id'])
                return user_dict
            return None
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving user by subscription ID: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by subscription ID: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_last_login(self, user_id: str):
        """Updates a user's last login timestamp."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s;", (user_id,))
            conn.commit()
            logger.info(f"User {user_id} last login updated.")
        except psycopg2.Error as e:
            logger.error(f"Database error updating user last login: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error updating user last login: {e}", exc_info=True)
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_status(self, user_id: str, new_status: str) -> bool:
        """Updates a user's account status."""
        if new_status not in USER_STATUSES:
            logger.warning(f"Attempted to set invalid user status: {new_status}")
            return False
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET status = %s WHERE id = %s;", (new_status, user_id))
            conn.commit()
            logger.info(f"User {user_id} status updated to {new_status}.")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database error updating user status: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating user status: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_email_verified_status(self, user_id: str, verified: bool) -> bool:
        """Updates a user's email verification status."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET email_verified = %s, status = %s WHERE id = %s;",
                           (verified, 'active' if verified else 'pending_email_verification', user_id))
            conn.commit()
            logger.info(f"User {user_id} email verified status updated to {verified}.")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database error updating email verified status: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating email verified status: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_password(self, user_id: str, new_password: str) -> Tuple[bool, str]:
        """Updates a user's password after validation."""
        is_strong, msg = self.validate_password_strength(new_password)
        if not is_strong:
            return False, msg

        hashed_password = self.hash_password(new_password)
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = %s, password_reset_token = NULL, password_reset_expires = NULL WHERE id = %s;", (hashed_password, user_id))
            conn.commit()
            logger.info(f"User {user_id} password updated.")
            return True, "Password updated successfully."
        except psycopg2.Error as e:
            logger.error(f"Database error updating user password: {e}", exc_info=True)
            return False, "Database error during password update."
        except Exception as e:
            logger.error(f"Unexpected error updating user password: {e}", exc_info=True)
            return False, "An unexpected error occurred during password update."
        finally:
            if conn:
                return_db_connection(conn)

    def generate_password_reset_token(self, email: str) -> Optional[str]:
        """Generates and stores a password reset token for a user."""
        user = self.get_user_by_email(email)
        if not user:
            logger.warning(f"Attempt to generate reset token for non-existent email: {email}")
            return None
        
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1) # Token valid for 1 hour

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_reset_token = %s, password_reset_expires = %s WHERE id = %s;",
                (token, expires_at, user['id'])
            )
            conn.commit()
            logger.info(f"Password reset token generated for user {user['id']}.")
            return token
        except psycopg2.Error as e:
            logger.error(f"Database error generating password reset token: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error generating password reset token: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def verify_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verifies a password reset token and returns user details if valid."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email FROM users WHERE password_reset_token = %s AND password_reset_expires > CURRENT_TIMESTAMP;",
                (token,)
            )
            user_data = cursor.fetchone()
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                user_dict = dict(zip(columns, user_data))
                user_dict['id'] = str(user_dict['id'])
                logger.info(f"Password reset token verified for user {user_dict['id']}.")
                return user_dict
            logger.warning(f"Invalid or expired password reset token: {token}")
            return None
        except psycopg2.Error as e:
            logger.error(f"Database error verifying password reset token: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying password reset token: {e}", exc_info=True)
            return None
        finally:
            if conn:
                return_db_connection(conn)

    def create_api_key(self, user_id: str, name: str, permissions: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Creates a new API key for a user.
        Returns (raw_key, encrypted_key_value) on success, (None, None) on failure.
        """
        if not all(p in API_KEY_PERMISSIONS for p in permissions):
            logger.warning(f"Invalid permissions provided for API key creation: {permissions}")
            return None, "Invalid permissions."

        raw_key = self.generate_api_key()
        key_hash = self.hash_api_key(raw_key)
        encrypted_key_value = self.encrypt_api_key(raw_key)

        sanitized_name = self._sanitize_input(name)
        
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO api_keys (user_id, key_hash, encrypted_key_value, name, permissions)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (user_id, key_hash, encrypted_key_value, sanitized_name, json.dumps(permissions))
            )
            conn.commit()
            logger.info(f"API key created for user {user_id}.")
            return raw_key, encrypted_key_value
        except psycopg2.Error as e:
            logger.error(f"Database error creating API key for user {user_id}: {e}", exc_info=True)
            return None, "Database error creating API key."
        except Exception as e:
            logger.error(f"Unexpected error creating API key for user {user_id}: {e}", exc_info=True)
            return None, "An unexpected error occurred during API key creation."
        finally:
            if conn:
                return_db_connection(conn)

    def get_api_keys_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieves all API keys for a given user, with decrypted values."""
        conn = None
        cursor = None
        api_keys = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, encrypted_key_value, permissions, status, created_at, last_used FROM api_keys WHERE user_id = %s;", (user_id,))
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            for row in rows:
                key_dict = dict(zip(columns, row))
                key_dict['id'] = str(key_dict['id'])
                # Decrypt the key value before returning
                key_dict['decrypted_key'] = self.decrypt_api_key(key_dict['encrypted_key_value'])
                # Parse permissions from JSONB
                key_dict['permissions'] = json.loads(key_dict['permissions']) if isinstance(key_dict['permissions'], str) else key_dict['permissions']
                api_keys.append(key_dict)
            return api_keys
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving API keys for user {user_id}: {e}", exc_info=True)
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving API keys for user {user_id}: {e}", exc_info=True)
            return []
        finally:
            if conn:
                return_db_connection(conn)

    def deactivate_api_key(self, api_key_id: str, user_id: str) -> bool:
        """Deactivates an API key by its ID for a specific user."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE api_keys SET status = 'inactive' WHERE id = %s AND user_id = %s;", (api_key_id, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                logger.info(f"API key {api_key_id} deactivated for user {user_id}.")
                return True
            logger.warning(f"API key {api_key_id} not found or does not belong to user {user_id}.")
            return False
        except psycopg2.Error as e:
            logger.error(f"Database error deactivating API key: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error deactivating API key: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def log_security_event(self, event_type: str, severity: str, description: str, user_id: Optional[str] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None, event_id: Optional[str] = None, event_source: Optional[str] = None):
        """Logs a security event to the database."""
        if severity not in {'low', 'medium', 'high', 'critical', 'info', 'warning'}:
            logger.warning(f"Invalid severity level provided: {severity}. Defaulting to 'info'.")
            severity = 'info'

        sanitized_event_type = self._sanitize_input(event_type)
        sanitized_description = self._sanitize_input(description)
        sanitized_ip_address = self._sanitize_input(ip_address) if ip_address else None
        sanitized_user_agent = self._sanitize_input(user_agent) if user_agent else None
        sanitized_event_id = self._sanitize_input(event_id) if event_id else None
        sanitized_event_source = self._sanitize_input(event_source) if event_source else None

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_events (user_id, event_type, severity, description, ip_address, user_agent, event_id, event_source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (user_id, sanitized_event_type, severity, sanitized_description, sanitized_ip_address, sanitized_user_agent, sanitized_event_id, sanitized_event_source)
            )
            conn.commit()
            logger.info(f"Security event logged: {event_type} (Severity: {severity})")
        except psycopg2.Error as e:
            logger.error(f"Database error logging security event: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error logging security event: {e}", exc_info=True)
        finally:
            if conn:
                return_db_connection(conn)

    def is_event_already_processed(self, event_id: str, event_source: str) -> bool:
        """Checks if a webhook event has already been processed to ensure idempotency."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM security_events WHERE event_id = %s AND event_source = %s LIMIT 1;",
                (event_id, event_source)
            )
            return cursor.fetchone() is not None
        except psycopg2.Error as e:
            logger.error(f"Database error checking event idempotency for {event_id}: {e}", exc_info=True)
            return False # Err on the side of re-processing if DB check fails
        except Exception as e:
            logger.error(f"Unexpected error checking event idempotency for {event_id}: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def mark_event_as_processed(self, event_id: str, event_source: str, event_type: str, description: str):
        """Marks a webhook event as processed by logging it."""
        self.log_security_event(
            event_type=event_type,
            severity='info',
            description=f"Webhook event processed: {description}",
            event_id=event_id,
            event_source=event_source
        )

    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves recent security events."""
        conn = None
        cursor = None
        events = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id, event_type, severity, description, ip_address, user_agent, timestamp, event_id, event_source FROM security_events ORDER BY timestamp DESC LIMIT %s;", (limit,))
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            for row in rows:
                event_dict = dict(zip(columns, row))
                event_dict['id'] = str(event_dict['id'])
                if event_dict['user_id']:
                    event_dict['user_id'] = str(event_dict['user_id'])
                events.append(event_dict)
            return events
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving security events: {e}", exc_info=True)
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving security events: {e}", exc_info=True)
            return []
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_subscription_status(self, user_id: str, new_status: str, is_trial: bool = False, auto_renewal: bool = True, subscription_id: Optional[str] = None, trial_ends: Optional[datetime] = None, stripe_customer_id: Optional[str] = None) -> bool:
        """
        Updates a user's subscription status, including trial details if applicable.
        Can also update Stripe customer and subscription IDs.
        """
        if new_status not in PAYMENT_STATUSES:
            logger.warning(f"Attempted to set invalid payment status: {new_status}")
            return False

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            trial_start = None
            trial_end = None
            if is_trial:
                trial_start = datetime.utcnow()
                trial_end = trial_ends if trial_ends else (datetime.utcnow() + timedelta(days=DEFAULT_TRIAL_DAYS))

            update_fields = {
                'subscription_status': new_status,
                'trial_start_date': trial_start,
                'trial_end_date': trial_end,
                'auto_renewal': auto_renewal
            }
            if subscription_id is not None:
                update_fields['stripe_subscription_id'] = subscription_id
            if stripe_customer_id is not None:
                update_fields['stripe_customer_id'] = stripe_customer_id

            set_clause = ", ".join([f"{k} = %s" for k in update_fields.keys()])
            values = list(update_fields.values())
            values.append(user_id)

            cursor.execute(
                f"UPDATE users SET {set_clause} WHERE id = %s;",
                tuple(values)
            )
            conn.commit()
            if cursor.rowcount > 0:
                logger.info(f"User {user_id} subscription status updated to {new_status}.")
                return True
            logger.warning(f"User {user_id} not found for subscription status update.")
            return False
        except psycopg2.Error as e:
            logger.error(f"Database error updating user subscription status: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating user subscription status: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def update_user_plan(self, user_id: str, new_plan: str) -> bool:
        """Updates a user's subscription plan."""
        if new_plan not in ALLOWED_PLANS:
            logger.warning(f"Attempted to set invalid plan: {new_plan}")
            return False
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET plan = %s WHERE id = %s;", (new_plan, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                logger.info(f"User {user_id} plan updated to {new_plan}.")
                return True
            logger.warning(f"User {user_id} not found for plan update.")
            return False
        except psycopg2.Error as e:
            logger.error(f"Database error updating user plan: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating user plan: {e}", exc_info=True)
            return False
        finally:
            if conn:
                return_db_connection(conn)

    def calculate_discounted_price(self, base_price: float, plan: str, billing_cycle: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates the discounted price based on plan, billing cycle, and user's trial eligibility.
        """
        discount_percentage = 0.0
        trial_applied = False
        
        # Apply plan-based discounts
        if plan == "basic":
            discount_percentage += 0.05 # 5% off
        elif plan == "professional":
            discount_percentage += 0.10 # 10% off
        elif plan == "business":
            discount_percentage += 0.15 # 15% off
        elif plan == "enterprise":
            discount_percentage += 0.20 # 20% off

        # Apply billing cycle discounts
        if billing_cycle == "yearly":
            discount_percentage += 0.10 # Additional 10% off for yearly

        # Check for trial eligibility
        if user_id:
            user = self.get_user_by_id(user_id)
            if user and user.get('subscription_status') == 'trial' and datetime.utcnow() < user.get('trial_end_date', datetime.min):
                # During trial, price is 0
                final_price = 0.0
                trial_applied = True
                logger.info(f"Trial period active for user {user_id}. Price set to 0.")
                return {
                    "base_price": base_price,
                    "plan": plan,
                    "billing_cycle": billing_cycle,
                    "discount_percentage": discount_percentage,
                    "final_price": final_price,
                    "currency": "USD", # Assuming USD
                    "trial_applied": trial_applied,
                    "message": "Trial period active, price is free."
                }
            elif user and user.get('subscription_status') == 'trial' and datetime.utcnow() >= user.get('trial_end_date', datetime.max):
                # Trial expired, update status
                self.update_user_subscription_status(user_id, 'past_due' if user.get('auto_renewal') else 'canceled')
                logger.info(f"Trial period expired for user {user_id}. Subscription status updated.")

        # Calculate price after discounts
        final_price = base_price * (1 - discount_percentage)
        final_price = max(0, round(final_price, 2)) # Ensure price is not negative and round to 2 decimal places

        return {
            "base_price": base_price,
            "plan": plan,
            "billing_cycle": billing_cycle,
            "discount_percentage": discount_percentage,
            "final_price": final_price,
            "currency": "USD", # Assuming USD
            "trial_applied": trial_applied,
            "message": "Price calculated successfully."
        }

    def populate_mock_threat_intelligence(self, num_entries: int = 100):
        """Populates the threat_intelligence table with mock data for demonstration."""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            threat_types = ["Malware", "Phishing", "DDoS", "Ransomware", "Insider Threat", "Zero-Day"]
            sources = ["ThreatFeedX", "OSINT", "InternalDetection", "DarkWebMonitor"]
            
            for _ in range(num_entries):
                indicator = f"ip-{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                threat_type = random.choice(threat_types)
                confidence = random.randint(50, 100)
                source = random.choice(sources)
                timestamp = datetime.utcnow() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))

                try:
                    cursor.execute(
                        """
                        INSERT INTO threat_intelligence (indicator, threat_type, confidence, source, timestamp, status)
                        VALUES (%s, %s, %s, %s, %s, 'active');
                        """,
                        (indicator, threat_type, confidence, source, timestamp)
                    )
                except psycopg2.errors.UniqueViolation:
                    # If indicator already exists, skip or update (for mock data, skipping is fine)
                    pass
            conn.commit()
            logger.info(f"Populated {num_entries} mock threat intelligence entries.")
        except psycopg2.Error as e:
            logger.error(f"Database error populating mock threat data: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error populating mock threat data: {e}", exc_info=True)
        finally:
            if conn:
                return_db_connection(conn)

    def deactivate_user_account(self, user_id: str) -> bool:
        """Deactivates a user's account."""
        return self.update_user_status(user_id, 'inactive')

    def suspend_user_account(self, user_id: str) -> bool:
        """Suspends a user's account."""
        return self.update_user_status(user_id, 'suspended')

    def activate_user_account(self, user_id: str) -> bool:
        """Activates a user's account."""
        return self.update_user_status(user_id, 'active')

    def get_all_users_by_role(self, role: str) -> List[Dict[str, Any]]:
        """Retrieves all users with a specific role."""
        conn = None
        cursor = None
        users = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, role, status FROM users WHERE role = %s;", (role,))
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            for row in rows:
                user_dict = dict(zip(columns, row))
                user_dict['id'] = str(user_dict['id'])
                users.append(user_dict)
            return users
        except psycopg2.Error as e:
            logger.error(f"Database error retrieving users by role {role}: {e}", exc_info=True)
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving users by role {role}: {e}", exc_info=True)
            return []
        finally:
            if conn:
                return_db_connection(conn)

# Example Usage (for testing purposes, typically removed or placed in a test file)
if __name__ == "__main__":
    # Ensure environment variables are set for testing
    os.environ["JWT_SECRET_KEY"] = "your_super_secret_jwt_key_for_testing_only_12345"
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode() # Generate a fresh key for testing
    os.environ["DATABASE_URL"] = "postgresql://user:password@host:port/database" # Replace with your test DB URL

    # Mock database utility functions if not truly connecting
    # from unittest.mock import MagicMock
    # get_db_connection = MagicMock(return_value=MagicMock())
    # return_db_connection = MagicMock()
    # close_db_pool = MagicMock()

    security_core = SecurityCore()
    
    # Test User Creation
    print("--- Test User Creation ---")
    new_user_id, msg = security_core.create_user(
        email="test_user@example.com",
        password="SecurePassword1!",
        first_name="Test",
        last_name="User",
        company_name="TestCo",
        is_trial_eligible=True
    )
    print(f"Create User Result: ID={new_user_id}, Message={msg}")

    if new_user_id:
        # Test User Login (simplified)
        print("\n--- Test User Login (simplified) ---")
        user_data = security_core.get_user_by_id(new_user_id)
        if user_data and security_core.check_password("SecurePassword1!", user_data['password_hash']):
            token = security_core.create_access_token(user_data['id'], user_data['role'])
            print(f"Login successful. Token: {token[:20]}...")
            verified_id = security_core.verify_access_token(token)
            print(f"Token verified, User ID: {verified_id}")
            security_core.update_user_last_login(new_user_id)
        else:
            print("Login failed.")

        # Test API Key Management
        print("\n--- Test API Key Management ---")
        raw_api_key, encrypted_api_key = security_core.create_api_key(new_user_id, "My First Key", ["read", "write"])
        print(f"Generated API Key: {raw_api_key}")
        print(f"Encrypted API Key: {encrypted_api_key}")

        user_api_keys = security_core.get_api_keys_for_user(new_user_id)
        print("User API Keys:")
        for key in user_api_keys:
            print(f"  ID: {key['id']}, Name: {key['name']}, Status: {key['status']}, Decrypted: {key['decrypted_key']}")
            security_core.deactivate_api_key(key['id'], new_user_id)
        
        user_api_keys_after_deactivation = security_core.get_api_keys_for_user(new_user_id)
        print("User API Keys (after deactivation):")
        for key in user_api_keys_after_deactivation:
            print(f"  ID: {key['id']}, Status: {key['status']}")

        # Test Security Event Logging
        print("\n--- Test Security Event Logging ---")
        security_core.log_security_event(
            user_id=new_user_id,
            event_type="Login Attempt",
            severity="info",
            description="Successful login from new IP",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0"
        )
        security_core.log_security_event(
            event_type="Unauthorized Access",
            severity="high",
            description="Attempt to access admin panel without privileges",
            ip_address="203.0.113.45"
        )
        events = security_core.get_security_events(limit=5)
        print("Recent Security Events:")
        for event in events:
            print(f"  [{event['timestamp']}] {event['event_type']} ({event['severity']}): {event['description']}")

        # Test Password Reset Flow
        print("\n--- Test Password Reset Flow ---")
        reset_token = security_core.generate_password_reset_token("test_user@example.com")
        if reset_token:
            print(f"Generated reset token: {reset_token}")
            verified_user = security_core.verify_password_reset_token(reset_token)
            if verified_user:
                print(f"Reset token verified for user: {verified_user['email']}")
                success, msg = security_core.update_user_password(verified_user['id'], "NewSecurePassword2!")
                print(f"Password update result: {success}, {msg}")
            else:
                print("Reset token verification failed.")
        else:
            print("Failed to generate reset token.")

        # Test Subscription Status and Plan Updates
        print("\n--- Test Subscription Status and Plan Updates ---")
        security_core.update_user_subscription_status(new_user_id, 'active')
        user_status = security_core.get_user_by_id(new_user_id)
        print(f"User {new_user_id} subscription status: {user_status['subscription_status']}")

        security_core.update_user_plan(new_user_id, 'professional')
        user_plan = security_core.get_user_by_id(new_user_id)
        print(f"User {new_user_id} plan: {user_plan['plan']}")

        # Test Price Calculation
        print("\n--- Test Price Calculation ---")
        base_price = 100.0
        print(f"Base Price: ${base_price}")

        # Trial user (should be free)
        user_id_trial = new_user_id # Use the same user for trial testing
        security_core.update_user_subscription_status(user_id_trial, 'trial', is_trial=True)
        trial_price = security_core.calculate_discounted_price(base_price, "professional", "monthly", user_id=user_id_trial)
        print(f"Trial Price: {json.dumps(trial_price, indent=2)}")

        # After trial (should be calculated price)
        # Manually set trial_end_date to past for testing expired trial
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET trial_end_date = %s WHERE id = %s;", (datetime.utcnow() - timedelta(days=1), user_id_trial))
        conn.commit()
        return_db_connection(conn)

        expired_trial_price = security_core.calculate_discounted_price(base_price, "professional", "monthly", user_id=user_id_trial)
        print(f"Expired Trial Price (should update status and calculate): {json.dumps(expired_trial_price, indent=2)}")
        
        # Regular user, monthly basic
        monthly_basic_price = security_core.calculate_discounted_price(base_price, "basic", "monthly")
        print(f"Monthly Basic Price: {json.dumps(monthly_basic_price, indent=2)}")

        # Regular user, yearly professional
        yearly_professional_price = security_core.calculate_discounted_price(base_price, "professional", "yearly")
        print(f"Yearly Professional Price: {json.dumps(yearly_professional_price, indent=2)}")

        # Test Mock Threat Data Population
        print("\n--- Test Mock Threat Data Population ---")
        security_core.populate_mock_threat_intelligence(num_entries=50)
        
        # Clean up user for re-runs
        try:
            print(f"\nCleaning up test user {new_user_id}...")
            conn_cleanup = get_db_connection()
            cursor_cleanup = conn_cleanup.cursor()
            cursor_cleanup.execute("DELETE FROM users WHERE id = %s", (new_user_id,))
            conn_cleanup.commit()
            return_db_connection(conn_cleanup)
            print(f"Test user {new_user_id} and associated data deleted.")
        except Exception as e:
            logger.error(f"Error during test user cleanup: {e}", exc_info=True)
