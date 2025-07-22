from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, File, UploadFile
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import jwt
import bcrypt
from enum import Enum
import boto3

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
import json
from twilio.rest import Client

ROOT_DIR = Path(__file__).parent.parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client.crm_db

# FastAPI app initialization
app = FastAPI(title="CRM 2.0 API", description="API para o sistema CRM 2.0", version="1.0.0")

# CORS configuration - CORRIGIDO para aceitar múltiplos domínios
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Para desenvolvimento local
        "https://crm-2-0-1-frontend.vercel.app",  # URL do frontend no Vercel
        "https://*.vercel.app",  # Permite qualquer subdomínio do Vercel
        "*"  # TEMPORÁRIO: permite qualquer origem (remover em produção)
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# JWT settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Twilio settings
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')

# Google OAuth settings
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI')

# Security
security = HTTPBearer()

# Modelos Pydantic básicos
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Rota raiz
@app.get("/")
def read_root():
    return {"message": "Welcome to CRM 2.0 API", "status": "online", "version": "1.0.0"}

# Rota de health check
@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow()}

# Rotas de autenticação básicas
@app.post("/auth/register", response_model=dict)
async def register_user(user: UserCreate):
    try:
        # Verificar se o usuário já existe
        existing_user = await db.users.find_one({"$or": [{"username": user.username}, {"email": user.email}]})
        if existing_user:
            raise HTTPException(status_code=400, detail="Username or email already registered")
        
        # Hash da senha
        hashed_password = get_password_hash(user.password)
        
        # Criar usuário
        user_dict = {
            "username": user.username,
            "email": user.email,
            "password": hashed_password,
            "full_name": user.full_name,
            "created_at": datetime.utcnow(),
            "is_active": True
        }
        
        result = await db.users.insert_one(user_dict)
        
        return {"message": "User created successfully", "user_id": str(result.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login", response_model=Token)
async def login_user(user: UserLogin):
    try:
        # Buscar usuário
        db_user = await db.users.find_one({"username": user.username})
        if not db_user or not verify_password(user.password, db_user["password"]):
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        
        # Criar token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Funções auxiliares
def get_current_user(token: str = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except jwt.PyJWTError:
        raise credentials_exception

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Rota protegida de exemplo
@app.get("/users/me")
async def read_users_me(current_user: str = Depends(get_current_user)):
    user = await db.users.find_one({"username": current_user})
    if user:
        user["_id"] = str(user["_id"])
        user.pop("password", None)  # Remover senha da resposta
        return user
    raise HTTPException(status_code=404, detail="User not found")

# Google OAuth2
@app.get("/auth/google")
async def google_auth():
    try:
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid'],
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        return {"url": authorization_url}
    except Exception as e:
        return {"error": f"Google auth setup error: {str(e)}"}

@app.get("/auth/google/callback")
async def google_callback(code: str):
    try:
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid'],
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        flow.fetch_token(code=code)
        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(credentials.id_token, requests.Request(), GOOGLE_CLIENT_ID)
        
        return {"message": "Google authentication successful", "user_info": id_info}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Twilio SMS
@app.post("/send-sms")
async def send_sms(to: str, message: str):
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        raise HTTPException(status_code=500, detail="Twilio credentials not configured")
    
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            to=to,
            from_=TWILIO_PHONE_NUMBER,
            body=message
        )
        return {"message": "SMS sent successfully", "sid": message.sid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Email integration (placeholder)
@app.post("/send-email")
async def send_email(to: str, subject: str, body: str):
    logging.info(f"Sending email to {to} with subject '{subject}' and body '{body}'")
    return {"message": "Email sent successfully (placeholder)"}

# Calendar integration (placeholder)
@app.post("/create-calendar-event")
async def create_calendar_event(credentials: str, summary: str, description: str, start_time: str, end_time: str):
    try:
        creds = Credentials.from_authorized_user_info(json.loads(credentials))
        service = build('calendar', 'v3', credentials=creds)

        event = {
            'summary': summary,
            'description': description,
            'start': {
                'dateTime': start_time,
                'timeZone': 'America/Sao_Paulo',
            },
            'end': {
                'dateTime': end_time,
                'timeZone': 'America/Sao_Paulo',
            },
        }

        event = service.events().insert(calendarId='primary', body=event).execute()
        return {"message": "Event created", "event_id": event.get('id')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# File upload (placeholder)
@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...)):
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        file_key = f"uploads/{uuid.uuid4()}-{file.filename}"

        s3_client.upload_fileobj(file.file, bucket_name, file_key)
        return {"message": "File uploaded successfully", "file_url": f"https://{bucket_name}.s3.amazonaws.com/{file_key}"}
    except Exception as e:
        return {"error": f"File upload error: {str(e)}"}

# Analytics (placeholder)
@app.get("/analytics/data")
async def get_analytics_data():
    return {"message": "Analytics data (placeholder)", "data": {"users": 100, "leads": 50, "deals": 20}}

# Notifications (placeholder)
@app.post("/send-notification")
async def send_notification(user_id: str, message: str):
    logging.info(f"Sending notification to user {user_id}: {message}")
    return {"message": "Notification sent (placeholder)"}

# Settings (placeholder)
@app.put("/update-settings")
async def update_settings(user_id: str, settings: Dict[str, Any]):
    logging.info(f"Updating settings for user {user_id}: {settings}")
    return {"message": "Settings updated (placeholder)"}

# Integrations (placeholder)
@app.post("/integrate")
async def integrate_service(service_name: str, config: Dict[str, Any]):
    logging.info(f"Integrating with {service_name} with config: {config}")
    return {"message": f"Integration with {service_name} successful (placeholder)"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

