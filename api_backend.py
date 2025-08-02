import os
import logging
from typing import Annotated, Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import JSONResponse
from pydantic import BaseModel, EmailStr

# --- Hardened Module Imports ---
from security_core import SecurityCore
from payment import PaymentProcessor
from email_automation import EmailAutomation
from utils.database import init_db_pool, close_db_pool

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Service Initialization ---
# These are initialized as singletons for the application's lifecycle.
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Myers Cybersecurity API",
    description="Backend API for user management, subscriptions, and security features.",
    version="1.0.0",
)
security_core = SecurityCore()
payment_processor = PaymentProcessor()
email_automation = EmailAutomation()

# --- FastAPI Lifecycle Events (Fixes Stateless Initialization) ---
@app.on_event("startup")
async def startup_event():
    """Initializes the database pool when the application starts."""
    logger.info("FastAPI application startup...")
    init_db_pool()
    security_core.init_database() # Ensure schema exists

@app.on_event("shutdown")
async def shutdown_event():
    """Closes the database pool when the application shuts down."""
    logger.info("FastAPI application shutdown...")
    close_db_pool()

# --- Middleware Configuration ---
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
allowed_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security & Dependencies ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> Dict[str, Any]:
    """Dependency to get the current authenticated user's data from a token."""
    user_id = security_core.verify_access_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = security_core.get_user_by_id(user_id)
    if not user or user['status'] != 'active':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not active.")
    return user

async def get_current_admin_user(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]) -> Dict[str, Any]:
    """Dependency to ensure the current user is an admin."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted: requires admin privileges."
        )
    return current_user

# --- Pydantic Models ---
class SignupModel(BaseModel):
    email: EmailStr
    password: str
    company_name: str
    first_name: str
    last_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserRoleUpdate(BaseModel):
    role: str

class AdminUserView(BaseModel):
    id: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company_name: Optional[str] = None
    role: str
    status: str
    subscription_status: Optional[str] = None
    email_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None

class CheckoutSessionRequest(BaseModel):
    price_id: str

class CheckoutSessionResponse(BaseModel):
    checkout_url: str

# --- API Endpoints ---
@app.get("/healthz", tags=["Status"])
async def health_check():
    """Provides a simple health check endpoint."""
    return {"status": "ok", "version": app.version}

@app.post("/token", response_model=Token, tags=["Authentication"])
@limiter.limit("10/minute")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Authenticates a user and returns a JWT access token.
    This endpoint is fully rewritten to use the hardened SecurityCore methods.
    """
    user = security_core.get_user_by_email(form_data.username)
    if not user or not security_core.check_password(form_data.password, user['password_hash']):
        logger.warning(f"Failed login attempt for {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user['status'] != 'active':
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is not active.")

    access_token = security_core.create_access_token(user_id=str(user['id']), role=user['role'])
    security_core.update_user(user['id'], {'last_login': datetime.now(timezone.utc)})
    logger.info(f"Token issued for user ID {user['id']}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def signup_user(signup_data: SignupModel):
    """
    Registers a new user.
    """
    user_id, message = security_core.create_user(
        email=signup_data.email,
        password=signup_data.password,
        company_name=signup_data.company_name,
        first_name=signup_data.first_name,
        last_name=signup_data.last_name,
    )
    if not user_id:
        logger.error(f"Signup failed for {signup_data.email}: {message}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)
    
    # Placeholder for sending a verification email
    # email_automation.send_verification_email(...)
    
    logger.info(f"New signup registered: {signup_data.email}")
    return {"message": "Signup successful. Please check your email to verify your account."}

@app.get("/users/me", tags=["Users"])
async def read_users_me(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    """Fetches the profile of the currently authenticated user."""
    current_user.pop('password_hash', None)
    return current_user

# --- Billing Endpoints ---
@app.post("/billing/create-checkout-session", response_model=CheckoutSessionResponse, tags=["Billing"])
async def create_checkout_session(
    checkout_request: CheckoutSessionRequest,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)]
):
    """
    Creates a Stripe checkout session for the authenticated user to start a subscription.
    """
    # These URLs should be configured in your environment for production
    success_url = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:3000/success")
    cancel_url = os.environ.get("STRIPE_CANCEL_URL", "http://localhost:3000/cancel")
    
    result = payment_processor.create_checkout_session(
        price_id=checkout_request.price_id,
        customer_email=current_user['email'],
        success_url=success_url,
        cancel_url=cancel_url
    )
    
    if "error" in result:
        logger.error(f"Failed to create checkout session for user {current_user['id']}: {result['error']}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create a payment session.")
        
    return result

# --- Admin Panel Endpoints ---
# NOTE: These endpoints require corresponding methods in `security_core.py`:
# - get_all_users()
# - get_security_events_for_user(user_id)

@app.get("/admin/users", response_model=List[AdminUserView], tags=["Admin"])
async def get_all_users(admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    """
    Retrieves a list of all users. Admin only.
    """
    users = security_core.get_all_users()
    return users

@app.put("/admin/users/{user_id}/role", tags=["Admin"])
async def update_user_role(user_id: str, role_update: UserRoleUpdate, admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    """
    Updates a user's role (promote/demote). Admin only.
    """
    if role_update.role not in ['user', 'admin']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified. Must be 'user' or 'admin'.")
    
    success = security_core.update_user(user_id, {'role': role_update.role})
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID {user_id} not found.")
    
    logger.info(f"Admin {admin_user['id']} updated user {user_id} role to {role_update.role}")
    return {"message": f"User {user_id} role updated to {role_update.role}."}

@app.get("/admin/users/{user_id}/events", tags=["Admin"])
async def get_user_events(user_id: str, admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    """
    Retrieves security events for a specific user. Admin only.
    """
    events = security_core.get_security_events_for_user(user_id)
    return events

# --- FIX APPLIED: Architectural Conflict Removed ---
# The /stripe-webhooks endpoint has been completely removed from this file.
# That functionality belongs exclusively in the `webhook_handler.py` service.
