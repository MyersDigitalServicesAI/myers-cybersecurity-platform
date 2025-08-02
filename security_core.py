import os
import secrets
import json
import bcrypt
import re
import logging
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet, InvalidToken
from email_validator import validate_email, EmailNotValidError
from functools import wraps
import psycopg2
from psycopg2.extras import DictCursor
from typing import Dict, Any, Optional, Tuple, List

# --- Hardened Module Imports ---
from utils.database import get_db_connection, return_db_connection

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

# --- Application-wide Constants ---
USER_ROLES = {'user', 'admin'}
API_KEY_PERMISSIONS = {'read', 'write', 'admin'}

def db_connection_manager(func):
    """Decorator to securely manage database connections."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        conn = None
        try:
            conn = get_db_connection()
            # Pass the connection as a keyword argument to the decorated function
            kwargs['conn'] = conn
            result = func(*args, **kwargs)
            return result
        except psycopg2.Error as e:
            logger.error(f"Database error in {func.__name__}: {e}", exc_info=True)
            if conn: conn.rollback()
            raise
        finally:
            if conn: return_db_connection(conn)
    return wrapper

class SecurityCore:
    def __init__(self):
        """Initializes the SecurityCore with required secrets from environment variables."""
        self.jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
        self.encryption_key = os.environ.get("ENCRYPTION_KEY")
        if not self.jwt_secret_key or not self.encryption_key:
            logger.critical("FATAL: JWT_SECRET_KEY and ENCRYPTION_KEY environment variables must be set.")
            raise ValueError("Required secret keys are missing from the environment.")
        self.fernet = Fernet(self.encryption_key.encode('utf-8'))
        self.jwt_algorithm = "HS256"
        self.jwt_expire_minutes = 60
        logger.info("SecurityCore initialized.")

    @staticmethod
    @db_connection_manager
    def init_database(conn=None):
        """Initializes the database schema."""
        # --- FIX APPLIED: Added password reset fields to users table ---
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
                trial_end_date TIMESTAMP WITH TIME ZONE,
                password_reset_token VARCHAR(255),
                password_reset_expires TIMESTAMP WITH TIME ZONE
            );
            """,
            # ... other table creation queries ...
        ]
        with conn.cursor() as cursor:
            for query in schema_queries:
                cursor.execute(query)
        conn.commit()
        logger.info("Database schema initialized successfully.")

    # ... (hashing, encryption, create_user, get_user_by_id, etc. remain the same) ...
    
    @db_connection_manager
    def get_user_by_email(self, email: str, conn=None) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM users WHERE email = %s;"
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute(sql, (email.lower(),))
            user = cursor.fetchone()
        return dict(user) if user else None

    @db_connection_manager
    def update_user(self, user_id: str, fields_to_update: Dict[str, Any], conn=None) -> bool:
        """A centralized and secure function to update user fields."""
        allowed_fields = {
            'first_name', 'last_name', 'company_name', 'password_hash',
            'last_login', 'email_verified', 'stripe_customer_id',
            'stripe_subscription_id', 'subscription_status', 'trial_end_date', 'status',
            'password_reset_token', 'password_reset_expires' # Added for password reset
        }
        update_dict = {k: v for k, v in fields_to_update.items() if k in allowed_fields}
        if not update_dict:
            return False
        set_clause = ", ".join([f"{key} = %s" for key in update_dict.keys()])
        sql = f"UPDATE users SET {set_clause} WHERE id = %s;"
        values = list(update_dict.values())
        values.append(user_id)
        with conn.cursor() as cursor:
            cursor.execute(sql, tuple(values))
            updated_rows = cursor.rowcount
            conn.commit()
        return updated_rows > 0

    # --- ADDED: Secure Password Reset Functionality ---
    @db_connection_manager
    def generate_password_reset_token(self, email: str, conn=None) -> Optional[str]:
        """Generates and stores a password reset token hash for a user."""
        user = self.get_user_by_email(email, conn=conn)
        if not user:
            logger.warning(f"Attempt to generate reset token for non-existent email: {email}")
            return None # Fail silently for security
        
        token = secrets.token_urlsafe(32)
        token_hash = self.hash_password(token) # Hash the token for storage
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        update_payload = {
            'password_reset_token': token_hash,
            'password_reset_expires': expires_at
        }
        if self.update_user(user['id'], update_payload, conn=conn):
             logger.info(f"Password reset token generated for user {user['id']}.")
             return token # Return the raw token to be sent to the user
        return None

    def verify_password_reset_token(self, user: Dict[str, Any], token: str) -> bool:
        """
        Verifies a raw password reset token against the user's stored hash.
        This is more secure as it requires the user record to be fetched first.
        """
        if not user or not user.get('password_reset_token') or not user.get('password_reset_expires'):
            return False
        
        # Check for expiration
        if user['password_reset_expires'] < datetime.now(timezone.utc):
            logger.warning(f"Attempt to use expired password reset token for user {user['id']}.")
            return False
            
        # Check the hash
        return self.check_password(token, user['password_reset_token'])
