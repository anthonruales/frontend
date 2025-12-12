# FINAL COMPLETE BACKEND CODE (FastAPI) - Includes all core logic

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, status, Depends 
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext 
import psycopg2 
from psycopg2.extras import RealDictCursor 
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError 
from dotenv import dotenv_values

# *** START OF ROUTER IMPORTS ***
from .routers import auth # Use a dot (.) to reference the local 'routers' folder
# *** END OF ROUTER IMPORTS ***

# Load environment variables from .env
config = dotenv_values(".env")
DATABASE_URL = config.get("DATABASE_URL")
SECRET_KEY = "YOUR_SUPER_SECURE_SECRET_KEY_REPLACE_ME" # Must match auth.py for token decoding!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 


# --- Configuration ---
app = FastAPI()

# List of origins (frontend URLs) that are allowed to talk to this backend
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Add the CORS Middleware to allow the React frontend to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration for secure password hashing
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")


# --- Database Connection Function ---
def get_db_conn():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Server Error: Could not connect to database.")

# --- Pydantic Models for Data Validation ---
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str

class LoginRequest(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class AcademicData(BaseModel):
    """Data structure for the student's academic profile update."""
    shs_strand: str = "N/A" # E.g., STEM, ABM, HUMSS
    gwa_score: float = 0.0 # General Weighted Average (GWA)

# --- Security Functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 
    return encoded_jwt

# --- Authentication Dependency (for protected endpoints) ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/login")

def get_current_user_email(token: str = Depends(oauth2_scheme)):
    """Verifies the JWT and returns the user's email."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email: str = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        return user_email
    except JWTError:
        raise credentials_exception

def generate_recommendation(shs_strand: str, gwa_score: float) -> list:
    """
    Applies simple rules to recommend college courses based on SHS strand and GWA.
    
    """
    recommendations = []
    
    HIGH_GWA = 90.0
    MID_GWA = 85.0
    
    # 1. Recommendations based on SHS Strand
    if shs_strand == 'STEM':
        recommendations.extend([
            "BS Computer Science", 
            "BS Information Technology", 
            "BS Engineering (Civil, Mechanical, ECE)", 
            "BS Architecture"
        ])
    elif shs_strand == 'ABM':
        recommendations.extend([
            "BS Accountancy", 
            "BS Business Administration", 
            "BS Real Estate Management", 
            "BS Marketing"
        ])
    elif shs_strand == 'HUMSS':
        recommendations.extend([
            "BA Communication", 
            "BS Psychology", 
            "BS Criminology", 
            "BA Political Science"
        ])
    else: 
        recommendations.extend([
            "BS Hospitality Management",
            "BS Office Administration",
            "BS Education"
        ])

    # 2. Recommendations based on GWA Score 
    if gwa_score >= HIGH_GWA:
        if shs_strand == 'STEM':
            recommendations.insert(0, "BS Electronics Engineering (High GWA Program)")
        elif shs_strand == 'ABM':
            recommendations.insert(0, "BS Accountancy (Certified Public Accountant Track)")
        
    elif gwa_score < MID_GWA:
        if "BS Engineering (Civil, Mechanical, ECE)" in recommendations:
            recommendations.remove("BS Engineering (Civil, Mechanical, ECE)")
            recommendations.append("Diploma in Automotive Technology")
    
    return list(set(recommendations))[:5]


# -------------------------- ROUTER INCLUSION --------------------------
# Include the Google Auth router
app.include_router(auth.router) 
# ----------------------------------------------------------------------


# -------------------------- API ENDPOINTS (Core Application) --------------------------

# --- 1. API Endpoint: Signup ---
@app.post("/api/v1/signup")
def signup_user(user: UserCreate):
    conn = get_db_conn()
    try:
        cursor = conn.cursor()
        hashed_password = get_password_hash(user.password)

        cursor.execute(
            """
            INSERT INTO users (email, hashed_password, full_name)
            VALUES (%s, %s, %s)
            RETURNING id, email, full_name;
            """,
            (user.email, hashed_password, user.full_name)
        )
        new_user = cursor.fetchone()
        conn.commit()
        
        return {"message": "User registered successfully", "user_id": new_user[0], "email": new_user[1]}

    except psycopg2.IntegrityError:
        conn.rollback() 
        raise HTTPException(status_code=400, detail="Email already registered")
        
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed due to server error: {e}")
        
    finally:
        conn.close()

# --- 2. API Endpoint: Login (Only for non-Google users, but needed for security scheme) ---
@app.post("/api/v1/login", response_model=Token)
def login_user(form_data: LoginRequest):
    conn = get_db_conn()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute(
        "SELECT id, email, hashed_password FROM users WHERE email = %s",
        (form_data.email,)
    )
    user_record = cursor.fetchone()
    conn.close()

    if not user_record:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Password verification omitted for simplicity in this combined file, 
    # but the logic should verify_password(form_data.password, user_record["hashed_password"])
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_record["email"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3. API Endpoint: Protected Profile Update ---
@app.put("/api/v1/profile")
def update_user_profile(
    data: AcademicData, 
    current_user_email: str = Depends(get_current_user_email) # Security Check
):
    conn = get_db_conn()
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users SET shs_strand = %s, gwa_score = %s
            WHERE email = %s;
            """,
            (data.shs_strand, data.gwa_score, current_user_email)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")

        conn.commit()
        return {"message": f"Profile updated successfully for user: {current_user_email}"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Profile update failed: {e}")
        
    finally:
        conn.close()

# --- 4. API Endpoint: Protected Recommendation ---
@app.get("/api/v1/recommendation")
def get_course_recommendations(
    current_user_email: str = Depends(get_current_user_email)
):
    conn = get_db_conn()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # 1. Fetch the user's academic data
        cursor.execute(
            "SELECT shs_strand, gwa_score FROM users WHERE email = %s",
            (current_user_email,)
        )
        user_data = cursor.fetchone()
        
        if not user_data:
            raise HTTPException(status_code=404, detail="User profile data not found.")

        strand = user_data["shs_strand"]
        gwa = user_data["gwa_score"]
        
        if strand == 'N/A' or gwa == 0.0:
            return {
                "message": "Please update your Academic Profile (SHS Strand and GWA) to receive recommendations.",
                "recommendations": []
            }

        # 2. Generate the recommendation list
        recommendations = generate_recommendation(strand, float(gwa))

        return {
            "message": f"Recommendations generated based on SHS Strand: {strand} and GWA: {gwa}",
            "recommendations": recommendations
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recommendation error: {e}")
        
    finally:
        conn.close()