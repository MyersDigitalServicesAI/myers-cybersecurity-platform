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
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Myers Cybersecurity API",
    description="Backend API for user management, subscriptions, and security features.",
    version="1.0.0",
)
security_core = SecurityCore()
payment_processor = PaymentProcessor()
email_automation = EmailAutomation()

# --- FastAPI Lifecycle Events ---
@app.on_event("startup")
async def startup_event():
    logger.info("FastAPI application startup...")
    init_db_pool()
    security_core.init_database()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("FastAPI application shutdown...")
    close_db_pool()

# --- Middleware ---
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security & Dependencies ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> Dict[str, Any]:
    user_id = security_core.verify_access_token(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = security_core.get_user_by_id(user_id)
    if not user or user['status'] != 'active':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User not active")
    return user

async def get_current_admin_user(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation requires admin privileges.")
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

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetSubmission(BaseModel):
    email: EmailStr
    token: str
    new_password: str
    
class UserProfileUpdate(BaseModel):
    first_name: str
    last_name: str

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str

class CheckoutSessionRequest(BaseModel):
    price_id: str

class CheckoutSessionResponse(BaseModel):
    checkout_url: str

class PortalSessionResponse(BaseModel):
    portal_url: str

class APIKeyCreate(BaseModel):
    name: str
    permissions: List[str]

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: datetime
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class NewAPIKeyInfo(BaseModel):
    message: str
    raw_key: str

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

# --- API Endpoints ---
@app.get("/healthz", tags=["Status"])
async def health_check():
    return {"status": "ok", "version": app.version}

@app.post("/token", response_model=Token, tags=["Authentication"])
@limiter.limit("10/minute")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = security_core.get_user_by_email(form_data.username)
    if not user or not security_core.check_password(form_data.password, user['password_hash']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    if user['status'] != 'active':
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is not active.")
    
    access_token = security_core.create_access_token(user_id=str(user['id']), role=user['role'])
    security_core.update_user(user['id'], {'last_login': datetime.now(timezone.utc)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def signup_user(signup_data: SignupModel):
    user_id, message = security_core.create_user(**signup_data.dict())
    if not user_id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)
    # email_automation.send_verification_email(...)
    return {"message": "Signup successful. Please verify your account."}

@app.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED, tags=["Authentication"])
async def forgot_password(payload: PasswordResetRequest):
    token = security_core.generate_password_reset_token(payload.email)
    if token:
        app_url = os.environ.get("APP_URL", "http://localhost:8501")
        reset_link = f"{app_url}/reset-password?token={token}&email={payload.email}"
        email_automation.send_password_reset_email(payload.email, reset_link)
    return {"message": "If an account with that email exists, a reset link has been sent."}

@app.post("/reset-password", tags=["Authentication"])
async def reset_password(payload: PasswordResetSubmission):
    user = security_core.get_user_by_email(payload.email)
    if not user or not security_core.verify_password_reset_token(user, payload.token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or email.")
    
    is_strong, reason = security_core.validate_password_strength(payload.new_password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)
    
    new_hash = security_core.hash_password(payload.new_password)
    update_payload = {'password_hash': new_hash, 'password_reset_token': None, 'password_reset_expires': None}
    if not security_core.update_user(user['id'], update_payload):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reset password.")
    
    return {"message": "Password reset successful."}

@app.get("/users/me", response_model=AdminUserView, tags=["Users"])
async def read_users_me(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    current_user.pop('password_hash', None)
    return current_user

@app.put("/users/me", tags=["Users"])
async def update_current_user_profile(profile_data: UserProfileUpdate, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    if not security_core.update_user(current_user['id'], profile_data.dict()):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update profile.")
    return {"message": "Profile updated successfully."}

@app.post("/users/me/change-password", tags=["Users"])
async def change_current_user_password(password_data: UserPasswordUpdate, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    if not security_core.check_password(password_data.current_password, current_user['password_hash']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password.")
    
    success, message = security_core.update_user_password(current_user['id'], password_data.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return {"message": message}

@app.get("/api-keys", response_model=List[APIKeyResponse], tags=["API Keys"])
async def get_user_api_keys(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    return security_core.get_api_keys_for_user(user_id=current_user['id'])

@app.post("/api-keys", response_model=NewAPIKeyInfo, status_code=status.HTTP_201_CREATED, tags=["API Keys"])
async def create_new_api_key(key_data: APIKeyCreate, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    raw_key, message = security_core.create_api_key(user_id=current_user['id'], name=key_data.name, permissions=key_data.permissions)
    if not raw_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)
    return {"message": message, "raw_key": raw_key}

@app.delete("/api-keys/{key_id}", status_code=status.HTTP_200_OK, tags=["API Keys"])
async def revoke_api_key(key_id: str, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    if not security_core.deactivate_api_key(key_id=key_id, user_id=current_user['id']):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found or you do not have permission to revoke it.")
    return {"message": "API key revoked successfully."}

@app.post("/billing/create-checkout-session", response_model=CheckoutSessionResponse, tags=["Billing"])
async def create_checkout_session(checkout_request: CheckoutSessionRequest, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    success_url = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:8501/dashboard")
    cancel_url = os.environ.get("STRIPE_CANCEL_URL", "http://localhost:8501/dashboard")
    result = payment_processor.create_checkout_session(price_id=checkout_request.price_id, customer_email=current_user['email'], success_url=success_url, cancel_url=cancel_url)
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create a payment session.")
    return result

@app.post("/billing/create-portal-session", response_model=PortalSessionResponse, tags=["Billing"])
async def create_portal_session(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    stripe_customer_id = current_user.get("stripe_customer_id")
    if not stripe_customer_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No billing account found for this user.")
    return_url = os.environ.get("APP_URL", "http://localhost:8501") + "/settings"
    result = payment_processor.create_customer_portal_session(customer_id=stripe_customer_id, return_url=return_url)
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create a billing portal session.")
    return result

@app.get("/admin/users", response_model=List[AdminUserView], tags=["Admin"])
async def get_all_users(admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    return security_core.get_all_users()

@app.put("/admin/users/{user_id}/role", tags=["Admin"])
async def update_user_role(user_id: str, role_update: UserRoleUpdate, admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    if role_update.role not in ['user', 'admin']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified.")
    if not security_core.update_user(user_id, {'role': role_update.role}):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID {user_id} not found.")
    logger.info(f"Admin {admin_user['id']} updated user {user_id} role to {role_update.role}")
    return {"message": f"User {user_id} role updated to {role_update.role}."}

@app.get("/admin/users/{user_id}/events", tags=["Admin"])
async def get_user_events(user_id: str, admin_user: Annotated[Dict[str, Any], Depends(get_current_admin_user)]):
    return security_core.get_security_events_for_user(user_id)

