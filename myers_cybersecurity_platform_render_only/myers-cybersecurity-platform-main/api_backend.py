from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import JSONResponse
from typing import Annotated
from pydantic import BaseModel, EmailStr
import os
import logging
import secrets

# Assuming these are adapted to be imported and used by FastAPI
from security_core import SecurityCore
from payment import PaymentProcessor
from email_automation import EmailAutomation

# Initialize services
db_security_core = SecurityCore()
payment_processor = PaymentProcessor()
email_automation = EmailAutomation()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("myers_logger")

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

# FastAPI app setup
app = FastAPI(
    title="Myers Cybersecurity API",
    description="Backend API for user management, subscriptions, and security features.",
    version="0.0.1",
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# CORS setup
allowed_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost,http://127.0.0.1").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

token_url_path = os.environ.get("TOKEN_URL_PATH", "/token")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url_path)

# --- Pydantic Models ---
class SignupModel(BaseModel):
    email: EmailStr
    password: str
    company: str
    first_name: str
    last_name: str
    plan: str

class APIKeyCreateModel(BaseModel):
    label: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetSubmission(BaseModel):
    token: str
    new_password: str
    confirm_password: str

# --- Utility Functions ---
async def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    user_id = db_security_core.verify_access_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id

# --- Exception Handlers ---
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please wait and try again."})

# --- API Endpoints ---
@app.get("/")
async def read_root():
    return {"message": "Welcome to the Myers Cybersecurity Backend!"}

@app.get("/healthz")
async def health_check():
    return {"status": "ok", "version": app.version}

@app.post("/token")
@limiter.limit("5/minute")
async def generate_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_auth_result, error_message = db_security_core.authenticate_user(
        form_data.username, form_data.password
    )
    if not user_auth_result:
        logger.warning(f"Failed login attempt for {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error_message
        )
    access_token = db_security_core.create_access_token({
        "sub": user_auth_result['email'],
        "id": user_auth_result['id']
    })
    logger.info(f"Token issued for user ID {user_auth_result['id']}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup")
async def signup_user(signup_data: SignupModel):
    user_id, message = db_security_core.create_user(
        email=signup_data.email,
        password=signup_data.password,
        company=signup_data.company,
        first_name=signup_data.first_name,
        last_name=signup_data.last_name,
        plan=signup_data.plan,
        email_verified=False
    )
    if not user_id:
        logger.error(f"Signup failed for {signup_data.email}: {message}")
        raise HTTPException(status_code=400, detail=message)
    email_automation.send_verification_email(signup_data.email)
    logger.info(f"New signup registered: {signup_data.email}")
    return {"message": "Signup successful. Please check your email to verify your account."}

@app.post("/api-keys")
async def create_api_key(api_key_data: APIKeyCreateModel, current_user_id: Annotated[str, Depends(get_current_user_id)]):
    api_key_value = secrets.token_urlsafe(32)
    result = db_security_core.add_api_key(current_user_id, api_key_data.label, api_key=api_key_value, service="custom", permissions="read")
    email_automation.send_admin_alert(f"API Key created by user ID {current_user_id}")
    logger.info(f"API key created for user ID {current_user_id}")
    return {"message": "API key created.", "key_id": result, "api_key": api_key_value}

@app.post("/forgot-password")
async def forgot_password(payload: PasswordResetRequest):
    token = db_security_core.generate_password_reset_token(payload.email)
    if token:
        app_url = os.environ.get("APP_URL", "http://localhost:8501")
        reset_link = f"{app_url}/?page=reset_password&token={token}"
        email_automation.send_password_reset_email(payload.email, reset_link)
    return {"message": "If an account with that email exists, a reset link has been sent."}

@app.post("/reset-password")
async def reset_password(payload: PasswordResetSubmission):
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    user_info = db_security_core.verify_password_reset_token(payload.token)
    if not user_info:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    is_strong, reason = db_security_core.validate_password_strength(payload.new_password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=reason)

    success = db_security_core.reset_user_password(user_info['user_id'], payload.new_password)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to reset password.")

    return {"message": "Password reset successful. You may now log in."}
