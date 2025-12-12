# backend/routers/auth.py

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import RedirectResponse
from dotenv import dotenv_values
import requests
from datetime import datetime, timedelta
import jwt 
import psycopg2 

# Assume .env file is in the parent directory of this file
config = dotenv_values("C:/Users/heda/Documents/CAPSTONE_LATEST/backend/.env") 
DATABASE_URL = config.get("DATABASE_URL")

def get_db_conn():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Server Error: Could not connect to database.")

# Load environment variables from .env
GOOGLE_CLIENT_ID = config.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config.get("GOOGLE_CLIENT_SECRET")
BACKEND_BASE_URL = config.get("BACKEND_BASE_URL")
FRONTEND_BASE_URL = config.get("FRONTEND_BASE_URL")

# IMPORTANT: Use your application's secure JWT secret key
SECRET_KEY = "YOUR_SUPER_SECURE_SECRET_KEY_REPLACE_ME" # MUST MATCH main.py
ALGORITHM = "HS256"

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"]
)

# Helper function to generate JWT token 
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7) 
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 1. Initiates the Google login flow 
@router.get("/google/login")
async def google_login():
    """
    Redirects the user to Google for authorization.
    """
    redirect_uri = f"{BACKEND_BASE_URL}/api/v1/auth/google/callback"
    
    # Google's authorization URL
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&scope=openid%20email%20profile&access_type=offline"
    )

# 2. Handles the callback from Google
@router.get("/google/callback")
async def google_callback(code: str):
    """
    Receives the authorization code, exchanges it for tokens, gets user data,
    and logs the user in/creates an account.
    """
    conn = get_db_conn()
    cursor = conn.cursor()
    redirect_uri = f"{BACKEND_BASE_URL}/api/v1/auth/google/callback"
    
    # --- Step A: Exchange code for token ---
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    token_r = requests.post(token_url, data=token_data)
    token_json = token_r.json()
    
    if "access_token" not in token_json:
        return RedirectResponse(
            url=f"{FRONTEND_BASE_URL}?error=google_auth_failed",
            status_code=status.HTTP_302_FOUND
        )

    access_token = token_json["access_token"]

    # --- Step B: Get user info using the token ---
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    user_info_r = requests.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
    user_info = user_info_r.json()

    google_email = user_info.get("email")
    google_name = user_info.get("name")
    
    if not google_email:
         return RedirectResponse(
            url=f"{FRONTEND_BASE_URL}?error=email_missing",
            status_code=status.HTTP_302_FOUND
        )

    # --- Step C: Find or create user in your database ---
    try:
        # Check if user exists
        cursor.execute("SELECT id, email, full_name FROM users WHERE email = %s", (google_email,))
        user_record = cursor.fetchone()

        if not user_record:
            # Create a new user if they don't exist
            cursor.execute(
                """
                INSERT INTO users (email, full_name, hashed_password, created_at)
                VALUES (%s, %s, %s, %s) RETURNING id, email;
                """,
                (google_email, google_name, "GOOGLE_OAUTH_USER_PLACEHOLDER", datetime.utcnow())
            )
            new_user_record = cursor.fetchone()
            user_email = new_user_record[1]
        else:
            user_email = user_record[1]

        conn.commit()

        # --- Step D: Generate application JWT and redirect ---
        app_jwt = create_access_token(data={"sub": user_email})

        # Redirect the user back to the frontend with the JWT in the URL
        return RedirectResponse(
            url=f"{FRONTEND_BASE_URL}?token={app_jwt}",
            status_code=status.HTTP_302_FOUND
        )
    except Exception as e:
        conn.rollback()
        print(f"Database/Login error: {e}")
        return RedirectResponse(
            url=f"{FRONTEND_BASE_URL}?error=server_issue",
            status_code=status.HTTP_302_FOUND
        )
    finally:
        conn.close()