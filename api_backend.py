from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
import os
import logging

# Assuming these are adapted to be imported and used by FastAPI
from security_core import SecurityCore
from payment import PaymentProcessor
from email_automation import EmailAutomation

# Initialize services (consider using FastAPI's Depends for dependency injection)
# For simplicity, initializing directly here for now, but DI is better for testing/modularity
db_security_core = SecurityCorePG()
payment_processor = PaymentProcessor()
email_automation = EmailAutomation()

app = FastAPI(
    title="Myers Cybersecurity API",
    description="Backend API for user management, subscriptions, and security features.",
    version="0.0.1",
)

# Configure OAuth2 for token-based authentication (example)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Utility Functions (can be moved to a separate file, e.g., auth_utils.py) ---
async def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    # This function would call db_security_core to verify the token and return user ID
    user_id = db_security_core.verify_access_token(token) # You'd implement this in SecurityCorePG
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id

# --- API Endpoints ---

@app.get("/")
async def read_root():
    return {"message": "Welcome to the FastAPI Backend!"}

@app.post("/token")
async def generate_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    # This endpoint handles user login and returns a JWT token
    user_auth_result, error_message = db_security_core.authenticate_user(
        form_data.username, form_data.password # username is email here
    )
    if not user_auth_result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error_message
        )

    # If successful, create and return an access token (JWT)
    access_token = db_security_core.create_access_token({"sub": user_auth_result['email'], "id": user_auth_result['id']}) # Implement this in SecurityCorePG
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup")
async def signup_user(signup_data: dict): # Use Pydantic models for real apps
    # Call db_security_core.register_user
    # Send verification email via email_automation
    return {"message": "User registered, please verify email."}

@app.post("/api-keys")
async def create_api_key(api_key_data: dict, current_user_id: Annotated[str, Depends(get_current_user_id)]):
    # Call db_security_core.add_api_key
    return {"message": "API key created."}

# ... other endpoints for password reset, subscription, etc.
