import os
import psycopg2
import secrets
import json
import bcrypt
import re
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from email_validator import validate_email, EmailNotValidError
import logging
from functools import wraps
import stripe

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_api_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            logging.info(f"{func.__name__} called with args={args[1:]}, kwargs={kwargs} - SUCCESS")
            return result
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {e}", exc_info=True)
            raise
    return wrapper

class SecurityCore:
    def __init__(self):
        self.database_url = os.getenv('DATABASE_URL')
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_database()

    def get_connection(self):
        return psycopg2.connect(self.database_url)

    def init_database(self):
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = 'users'
                );
            """)
            result = cursor.fetchone()
            if result and result[0]:
                conn.close()
                return

            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS api_keys (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                encrypted_key TEXT NOT NULL,
                service VARCHAR(255) NOT NULL,
                permissions VARCHAR(50) DEFAULT 'read',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

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

            conn.commit()
        except Exception as e:
            logging.error(f"Database initialization failed: {e}", exc_info=True)
            raise
        finally:
            if conn:
                conn.close()

    def get_or_create_encryption_key(self):
        key_path = 'encryption.key'
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                return Fernet(key_file.read())
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
            return Fernet(key)

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password, hash_string):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_string.encode('utf-8'))
        except Exception:
            return False

    def validate_email_input(self, email):
        try:
            validated_email = validate_email(email)
            return validated_email.email
        except EmailNotValidError:
            return None

    def validate_password_strength(self, password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        return True, "Password is strong"

class PaymentProcessor:
    def __init__(self):
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

    def create_customer(self, email):
        customer = stripe.Customer.create(email=email)
        return customer.id

    def create_subscription(self, customer_id, price_id):
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{"price": price_id}],
            payment_behavior='default_incomplete',
            expand=["latest_invoice.payment_intent"]
        )
        return subscription

    def cancel_subscription(self, subscription_id):
        stripe.Subscription.delete(subscription_id)

    def get_invoice_status(self, invoice_id):
        invoice = stripe.Invoice.retrieve(invoice_id)
        return invoice.status

    def sanitize_input(self, input_text, max_length=255):
        if not input_text:
            return ""
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', str(input_text))
        sanitized = sanitized.strip()[:max_length]
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;').replace("'", '&#x27;')
        return sanitized

    def encrypt_api_key(self, api_key):
        return self.encryption_key.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key):
        return self.encryption_key.decrypt(encrypted_key.encode()).decode()

    @log_api_call
    def promote_to_admin(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET role = 'admin', updated_at = CURRENT_TIMESTAMP WHERE id = %s
        """, (user_id,))
        conn.commit()
        conn.close()

    @log_api_call
    def demote_to_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET role = 'user', updated_at = CURRENT_TIMESTAMP WHERE id = %s
        """, (user_id,))
        conn.commit()
        conn.close()

    def create_user(self, email, password, company, first_name, last_name, plan, phone="", job_title="", billing_period="monthly"):
        validated_email = self.validate_email_input(email)
        if not validated_email:
            return None, "Invalid email format"
        is_valid, password_message = self.validate_password_strength(password)
        if not is_valid:
            return None, password_message
        company = self.sanitize_input(company, 100)
        first_name = self.sanitize_input(first_name, 50)
        last_name = self.sanitize_input(last_name, 50)
        phone = self.sanitize_input(phone, 20)
        job_title = self.sanitize_input(job_title, 100)
        allowed_plans = ['essentials', 'basic', 'professional', 'business', 'enterprise']
        if plan not in allowed_plans:
            return None, "Invalid plan selected"
        user_id = secrets.token_urlsafe(16)
        password_hash = self.hash_password(password)
        trial_start = datetime.now()
        trial_end = trial_start + timedelta(days=30)
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (id, email, password_hash, company, first_name, last_name, 
                                   phone, job_title, plan, trial_start_date, trial_end_date, 
                                   is_trial, billing_period, auto_renewal, trial_ends)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (user_id, validated_email, password_hash, company, first_name, last_name, 
                  phone, job_title, plan, trial_start, trial_end, True, billing_period, True, trial_end))
            conn.commit()
            return user_id, "Trial token generation pending"
        except psycopg2.IntegrityError as e:
            if 'email' in str(e):
                return None, "Email address already exists"
            return None, "Failed to create user account"
        except Exception as e:
            return None, f"Database error: {str(e)}"
        finally:
            conn.close()

    def get_trial_discount_eligibility(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT trial_start_date, is_trial FROM users WHERE id = %s', (user_id,))
        result = cursor.fetchone()
        conn.close()
        if not result or not result[1]:
            return False
        trial_start = result[0]
        days_since_trial = (datetime.now() - trial_start).days
        return days_since_trial <= 15

    def calculate_discounted_price(self, base_price, plan_name, billing_period="monthly", user_id=None):
        discounts = []
        final_price = base_price - 10
        discounts.append("$10 auto-renewal savings")

        if billing_period == "yearly":
            yearly_price = final_price * 10
            yearly_savings = (base_price * 12) - yearly_price
            discounts.append(f"2 months FREE (save ${yearly_savings}/year)")

            trial_discount = 0
            if user_id and self.get_trial_discount_eligibility(user_id):
                trial_discount = yearly_price * 0.25
                yearly_price -= trial_discount
                discounts.append(f"25% trial conversion discount (save ${trial_discount:.0f})")

            return {
                'monthly_price': final_price,
                'yearly_price': yearly_price,
                'total_savings': yearly_savings + trial_discount,
                'discounts': discounts
            }

        if user_id and self.get_trial_discount_eligibility(user_id):
            trial_savings = final_price * 0.25 * 3
            discounts.append(f"25% off first 3 months (save ${trial_savings:.0f})")

        return {
            'monthly_price': final_price,
            'yearly_price': None,
            'total_savings': 10,
            'discounts': discounts
        }

    def authenticate_user(self, email, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, role, status FROM users WHERE email = %s', (email,))
        result = cursor.fetchone()
        if result and self.verify_password(password, result[1]):
            user_id, _, role, status = result
            cursor.execute('UPDATE users SET last_login = %s WHERE id = %s', (datetime.now(), user_id))
            conn.commit()
            conn.close()
            return {'id': user_id, 'role': role, 'status': status}
        conn.close()
        return None

    def get_user_details(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, company, first_name, last_name, phone, job_title, 
                   plan, role, status, trial_ends, payment_status
            FROM users WHERE id = %s
        ''', (user_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'email': result[0], 'company': result[1], 'first_name': result[2],
                'last_name': result[3], 'phone': result[4], 'job_title': result[5],
                'plan': result[6], 'role': result[7], 'status': result[8],
                'trial_ends': result[9], 'payment_status': result[10]
            }
        return None

    def add_api_key(self, user_id, name, api_key, service, permissions="read"):
        key_id = secrets.token_urlsafe(16)
        encrypted_key = self.encrypt_api_key(api_key)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO api_keys (id, user_id, name, encrypted_key, service, permissions)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (key_id, user_id, name, encrypted_key, service, permissions))
        conn.commit()
        conn.close()
        self.log_security_event(user_id, "api_key_created", "info", f"API key '{name}' created for service '{service}'")
        return key_id

    def get_user_api_keys(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, encrypted_key, service, permissions, created_at FROM api_keys WHERE user_id = %s', (user_id,))
        keys = cursor.fetchall()
        conn.close()
        return keys
