import os
import secrets
import json
import bcrypt
import re
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet, InvalidToken
from email_validator import validate_email, EmailNotValidError
from functools import wraps
import psycopg2
from psycopg2 import pool
from psycopg2.extras import DictCursor
from typing import Dict, Any, Optional, Tuple, List

# --- Module-level logger setup ---
# It's best practice to configure logging once at the application's entry point.
# This basicConfig is a fallback.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Application-wide Constants for type safety and consistency ---
USER_ROLES = {'user', 'admin'}
USER_STATUSES = {'active', 'inactive', 'suspended', 'pending_email_verification'}
API_KEY_PERMISSIONS = {'read', 'write', 'admin'}

# --- Database Connection Pool (global, to be initialized once) ---
db_pool = None

def init_db_pool():
    """
    Initializes the PostgreSQL connection pool.
    This function should be called once when the application starts.
    """
    global db_pool
    if db_pool:
        logger.warning("Database pool already initialized.")
        return
        
    try:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            logger.critical("FATAL: DATABASE_URL environment variable not set.")
            raise ValueError("DATABASE_URL is required for database operations.")
        db_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1, 
            maxconn=10, 
            dsn=db_url
        )
        logger.info("Database connection pool created successfully.")
    except psycopg2.Error as e:
        logger.critical(f"Failed to create database connection pool: {e}", exc_info=True)
        raise

def close_db_pool():
    """Closes all connections in the pool. Call on application shutdown."""
    global db_pool
    if db_pool:
        db_pool.closeall()
        logger.info("Database connection pool closed.")

def db_connection_manager(func):
    """
    Decorator to securely manage database connections from the pool.
    It acquires a connection, passes it to the function, and ensures it's returned.
    This fixes the "Insecure Database Connection Handling" finding.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        global db_pool
        if not db_pool:
            logger.error("Database pool is not initialized. Cannot execute function.")
            raise ConnectionError("Database connection pool is not available.")
        
        conn = None
        try:
            conn = db_pool.getconn()
            # The decorated function will now receive 'conn' as its second argument
            # after 'self'.
            result = func(args[0], conn, *args[1:], **kwargs)
            return result
        except psycopg2.Error as e:
            logger.error(f"Database error in {func.__name__}: {e}", exc_info=True)
            if conn:
                conn.rollback() # Rollback transaction on error
            raise # Re-raise the exception to be handled by the caller
        finally:
            if conn:
                db_pool.putconn(conn)
    return wrapper

class SecurityCore:
    """
    Manages core security operations: user authentication, authorization,
    and secure data handling.
    """
    def __init__(self):
        """
        Initializes the SecurityCore with required secrets from environment variables.
        """
        # --- HIGH-PRIORITY FIX APPLIED (Improper Key Generation) ---
        # Keys are now fetched directly and will cause a startup failure if not present.
        self.jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
        self.encryption_key = os.environ.get("ENCRYPTION_KEY")

        if not self.jwt_secret_key:
            logger.critical("FATAL: JWT_SECRET_KEY environment variable not set.")
            raise ValueError("JWT_SECRET_KEY is required.")
        if not self.encryption_key:
            logger.critical("FATAL: ENCRYPTION_KEY environment variable not set.")
            raise ValueError("ENCRYPTION_KEY is required.")
            
        self.fernet = Fernet(self.encryption_key.encode('utf-8'))
        self.jwt_algorithm = "HS256"
        self.jwt_expire_minutes = 60
        logger.info("SecurityCore initialized successfully.")

    @staticmethod
    @db_connection_manager
    def init_database(self, conn):
        """
        Initializes the database schema. Should be run once on application startup.
        """
        # --- FIX APPLIED (Separation of Concerns) ---
        # This function is now static and only handles schema creation.
        # Mock data population is removed.
        # Added CHECK constraints for data integrity.
        # Standardized on TIMESTAMP WITH TIME ZONE for all timestamps.
        
        schema_queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                company_name VARCHAR(255),
                role VARCHAR(50) DEFAULT 'user' NOT NULL CHECK (role IN ('user', 'admin')),
                status VARCHAR(50) DEFAULT 'pending_email_verification' NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE,
                email_verified BOOLEAN DEFAULT FALSE,
                stripe_customer_id VARCHAR(255) UNIQUE,
                stripe_subscription_id VARCHAR(255) UNIQUE,
                subscription_status VARCHAR(50) DEFAULT 'unpaid',
                trial_end_date TIMESTAMP WITH TIME ZONE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                key_prefix VARCHAR(8) UNIQUE NOT NULL,
                key_hash VARCHAR(255) NOT NULL,
                encrypted_key TEXT NOT NULL,
                permissions JSONB DEFAULT '[]'::jsonb,
                status VARCHAR(50) DEFAULT 'active' NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP WITH TIME ZONE,
                expires_at TIMESTAMP WITH TIME ZONE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id BIGSERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                event_type VARCHAR(100) NOT NULL,
                severity VARCHAR(50) NOT NULL,
                description TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                event_id VARCHAR(255),
                event_source VARCHAR(100)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_idempotency ON security_events(event_id, event_source);"
        ]
        
        with conn.cursor() as cursor:
            for query in schema_queries:
                cursor.execute(query)
        conn.commit()
        logger.info("Database schema initialized successfully.")

    # --- Hashing and Encryption ---
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def encrypt_data(self, data: str) -> str:
        return self.fernet.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> Optional[str]:
        try:
            return self.fernet.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            logger.error("Failed to decrypt data: Invalid or malformed token.")
            return None

    # --- User Management ---
    @db_connection_manager
    def create_user(self, conn, email: str, password: str, first_name: str, last_name: str, company_name: str, role: str = 'user') -> Tuple[Optional[str], str]:
        if not self.validate_email_input(email):
            return None, "Invalid email format."
        
        is_strong, msg = self.validate_password_strength(password)
        if not is_strong:
            return None, msg

        hashed_password = self.hash_password(password)
        
        sql = """
        INSERT INTO users (email, password_hash, first_name, last_name, company_name, role)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
        """
        try:
            with conn.cursor() as cursor:
                cursor.execute(sql, (email.lower(), hashed_password, first_name, last_name, company_name, role))
                user_id = cursor.fetchone()[0]
                conn.commit()
            logger.info(f"User created successfully with email {email}.")
            return str(user_id), "User created successfully."
        except psycopg2.errors.UniqueViolation:
            logger.warning(f"Attempt to create user with existing email: {email}")
            return None, "An account with this email already exists."
        except psycopg2.Error as e:
            logger.error(f"Database error during user creation: {e}", exc_info=True)
            return None, "A database error occurred."

    @db_connection_manager
    def get_user_by_email(self, conn, email: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM users WHERE email = %s;"
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute(sql, (email.lower(),))
            user = cursor.fetchone()
        return dict(user) if user else None

    @db_connection_manager
    def get_user_by_id(self, conn, user_id: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM users WHERE id = %s;"
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute(sql, (user_id,))
            user = cursor.fetchone()
        return dict(user) if user else None

    @db_connection_manager
    def update_user(self, conn, user_id: str, fields_to_update: Dict[str, Any]) -> bool:
        """
        A centralized and secure function to update user fields.
        This fixes the SQL Injection and Consolidate Logic findings.
        """
        allowed_fields = {
            'first_name', 'last_name', 'company_name', 'password_hash',
            'last_login', 'email_verified', 'stripe_customer_id',
            'stripe_subscription_id', 'subscription_status', 'trial_end_date', 'status'
        }
        
        update_dict = {k: v for k, v in fields_to_update.items() if k in allowed_fields}

        if not update_dict:
            logger.warning("update_user called with no valid fields to update.")
            return False

        # Securely build the SET clause
        set_clause = ", ".join([f"{key} = %s" for key in update_dict.keys()])
        sql = f"UPDATE users SET {set_clause} WHERE id = %s;"
        
        values = list(update_dict.values())
        values.append(user_id)

        try:
            with conn.cursor() as cursor:
                cursor.execute(sql, tuple(values))
                updated_rows = cursor.rowcount
                conn.commit()
            if updated_rows > 0:
                logger.info(f"User {user_id} updated fields: {list(update_dict.keys())}")
                return True
            else:
                logger.warning(f"User {user_id} not found for update.")
                return False
        except psycopg2.Error as e:
            logger.error(f"Database error updating user {user_id}: {e}", exc_info=True)
            return False

    # --- API Key Management ---
    @db_connection_manager
    def create_api_key(self, conn, user_id: str, name: str, permissions: List[str], expires_in_days: Optional[int] = None) -> Tuple[Optional[str], str]:
        """
        Creates a new API key. Returns the raw key for display ONCE.
        """
        raw_key = f"mdc_{secrets.token_urlsafe(32)}"
        key_prefix = raw_key[:8]
        key_hash = self.hash_password(raw_key)
        encrypted_key = self.encrypt_data(raw_key)
        expires_at = (datetime.utcnow() + timedelta(days=expires_in_days)) if expires_in_days else None

        sql = """
        INSERT INTO api_keys (user_id, name, key_prefix, key_hash, encrypted_key, permissions, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
        """
        try:
            with conn.cursor() as cursor:
                cursor.execute(sql, (user_id, name, key_prefix, key_hash, encrypted_key, json.dumps(permissions), expires_at))
                conn.commit()
            logger.info(f"API key '{name}' created for user {user_id}.")
            return raw_key, "API key created successfully."
        except psycopg2.Error as e:
            logger.error(f"Database error creating API key for user {user_id}: {e}", exc_info=True)
            return None, "A database error occurred."

    @db_connection_manager
    def validate_api_key(self, conn, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Validates a raw API key and returns its details if valid.
        """
        if not api_key or len(api_key) < 8:
            return None
            
        prefix = api_key[:8]
        sql = "SELECT * FROM api_keys WHERE key_prefix = %s AND status = 'active';"
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute(sql, (prefix,))
            key_data = cursor.fetchone()

        if not key_data:
            return None

        if key_data['expires_at'] and key_data['expires_at'].replace(tzinfo=None) < datetime.utcnow():
            logger.warning(f"Attempt to use expired API key with prefix {prefix}.")
            # Optionally, you could deactivate the key here.
            return None

        if self.check_password(api_key, key_data['key_hash']):
            update_sql = "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = %s;"
            with conn.cursor() as cursor:
                cursor.execute(update_sql, (key_data['id'],))
                conn.commit()
            return dict(key_data)
        
        return None

    # --- Validation Helpers ---
    def validate_email_input(self, email: str) -> bool:
        try:
            validate_email(email, check_deliverability=False)
            return True
        except EmailNotValidError:
            return False

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        if len(password) < 10:
            return False, "Password must be at least 10 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain an uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain a lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain a digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain a special character."
        return True, "Password is strong."

