import os
import logging
from typing import Annotated, Dict, Any
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
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or email.")
    
    if not security_core.verify_password_reset_token(user, payload.token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token.")

    is_strong, reason = security_core.validate_password_strength(payload.new_password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)
    
    new_hash = security_core.hash_password(payload.new_password)
    update_payload = {
        'password_hash': new_hash,
        'password_reset_token': None,
        'password_reset_expires': None
    }
    if not security_core.update_user(user['id'], update_payload):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reset password.")
    
    return {"message": "Password reset successful."}

@app.get("/users/me", tags=["Users"])
async def read_users_me(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    current_user.pop('password_hash', None)
    return current_user
