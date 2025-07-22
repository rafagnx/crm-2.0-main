import os
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import uvicorn

# Configurações
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuração do MongoDB
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "crm_kanban")

# Configuração de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Inicialização do FastAPI
app = FastAPI(title="CRM Kanban API", version="1.0.0")

# Configuração CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, especifique os domínios permitidos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cliente MongoDB
client = None
db = None

@app.on_event("startup")
async def startup_db_client():
    global client, db
    try:
        client = AsyncIOMotorClient(MONGODB_URL)
        db = client[DATABASE_NAME]
        # Teste a conexão
        await client.admin.command('ping')
        print(f"Conectado ao MongoDB: {DATABASE_NAME}")
    except Exception as e:
        print(f"Erro ao conectar ao MongoDB: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()

# Modelos Pydantic
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class LeadCreate(BaseModel):
    title: str
    company: Optional[str] = None
    contact_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status: str = "novo"
    tags: List[str] = []
    notes: Optional[str] = None
    value: float = 0.0
    priority: str = "medium"
    assigned_to: Optional[str] = None
    source: Optional[str] = None
    next_follow_up: Optional[datetime] = None
    expected_close_date: Optional[datetime] = None

class LeadUpdate(BaseModel):
    title: Optional[str] = None
    company: Optional[str] = None
    contact_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    value: Optional[float] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    source: Optional[str] = None
    next_follow_up: Optional[datetime] = None
    expected_close_date: Optional[datetime] = None

class KanbanMove(BaseModel):
    lead_id: str
    new_status: str
    new_position: int

class CalendarEvent(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    event_type: str = "meeting"
    lead_id: Optional[str] = None

# Funções utilitárias
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise credentials_exception
    return user

def serialize_doc(doc):
    """Converte ObjectId para string em documentos MongoDB"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(item) for item in doc]
    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if key == "_id":
                result["id"] = str(value)
            elif isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, dict):
                result[key] = serialize_doc(value)
            elif isinstance(value, list):
                result[key] = serialize_doc(value)
            else:
                result[key] = value
        return result
    return doc

# Rotas de autenticação
@app.post("/api/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Verificar se o usuário já existe
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Criar novo usuário
    hashed_password = get_password_hash(user_data.password)
    user_doc = {
        "name": user_data.name,
        "email": user_data.email,
        "password": hashed_password,
        "role": user_data.role,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    
    # Criar token de acesso
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(result.inserted_id)}, expires_delta=access_token_expires
    )
    
    user_response = UserResponse(
        id=str(result.inserted_id),
        name=user_doc["name"],
        email=user_doc["email"],
        role=user_doc["role"],
        created_at=user_doc["created_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.post("/api/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    # Verificar se o usuário existe
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )
    
    # Criar token de acesso
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["_id"])}, expires_delta=access_token_expires
    )
    
    user_response = UserResponse(
        id=str(user["_id"]),
        name=user["name"],
        email=user["email"],
        role=user["role"],
        created_at=user["created_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=str(current_user["_id"]),
        name=current_user["name"],
        email=current_user["email"],
        role=current_user["role"],
        created_at=current_user["created_at"]
    )

# Rotas de leads
@app.post("/api/leads")
async def create_lead(lead_data: LeadCreate, current_user: dict = Depends(get_current_user)):
    lead_doc = lead_data.dict()
    lead_doc["created_by"] = str(current_user["_id"])
    lead_doc["created_at"] = datetime.utcnow()
    lead_doc["updated_at"] = datetime.utcnow()
    lead_doc["position"] = 0  # Posição no kanban
    
    result = await db.leads.insert_one(lead_doc)
    lead_doc["_id"] = result.inserted_id
    
    # Log da atividade
    activity = {
        "user_id": str(current_user["_id"]),
        "lead_id": str(result.inserted_id),
        "action": "created",
        "details": f"Lead '{lead_data.title}' foi criado",
        "timestamp": datetime.utcnow()
    }
    await db.activities.insert_one(activity)
    
    return serialize_doc(lead_doc)

@app.get("/api/leads")
async def get_leads(current_user: dict = Depends(get_current_user)):
    leads = await db.leads.find({"created_by": str(current_user["_id"])}).to_list(1000)
    return serialize_doc(leads)

@app.get("/api/leads/{lead_id}")
async def get_lead(lead_id: str, current_user: dict = Depends(get_current_user)):
    try:
        lead = await db.leads.find_one({
            "_id": ObjectId(lead_id),
            "created_by": str(current_user["_id"])
        })
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        return serialize_doc(lead)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid lead ID")

@app.put("/api/leads/{lead_id}")
async def update_lead(lead_id: str, lead_data: LeadUpdate, current_user: dict = Depends(get_current_user)):
    try:
        update_data = {k: v for k, v in lead_data.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.leads.update_one(
            {"_id": ObjectId(lead_id), "created_by": str(current_user["_id"])},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        updated_lead = await db.leads.find_one({"_id": ObjectId(lead_id)})
        
        # Log da atividade
        activity = {
            "user_id": str(current_user["_id"]),
            "lead_id": lead_id,
            "action": "updated",
            "details": f"Lead '{updated_lead['title']}' foi atualizado",
            "timestamp": datetime.utcnow()
        }
        await db.activities.insert_one(activity)
        
        return serialize_doc(updated_lead)
    except Exception as e:
        if "Lead not found" in str(e):
            raise e
        raise HTTPException(status_code=400, detail="Invalid lead ID")

@app.delete("/api/leads/{lead_id}")
async def delete_lead(lead_id: str, current_user: dict = Depends(get_current_user)):
    try:
        lead = await db.leads.find_one({
            "_id": ObjectId(lead_id),
            "created_by": str(current_user["_id"])
        })
        
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        await db.leads.delete_one({"_id": ObjectId(lead_id)})
        
        # Log da atividade
        activity = {
            "user_id": str(current_user["_id"]),
            "lead_id": lead_id,
            "action": "deleted",
            "details": f"Lead '{lead['title']}' foi excluído",
            "timestamp": datetime.utcnow()
        }
        await db.activities.insert_one(activity)
        
        return {"message": "Lead deleted successfully"}
    except Exception as e:
        if "Lead not found" in str(e):
            raise e
        raise HTTPException(status_code=400, detail="Invalid lead ID")

# Rotas do Kanban
@app.get("/api/kanban")
async def get_kanban_data(current_user: dict = Depends(get_current_user)):
    # Definir as colunas do kanban
    columns = [
        {"status": "novo", "title": "Novo", "color": "#3B82F6"},
        {"status": "qualificado", "title": "Qualificado", "color": "#10B981"},
        {"status": "proposta", "title": "Proposta", "color": "#F59E0B"},
        {"status": "negociacao", "title": "Negociação", "color": "#EF4444"},
        {"status": "fechado_ganho", "title": "Fechado (Ganho)", "color": "#059669"},
        {"status": "fechado_perdido", "title": "Fechado (Perdido)", "color": "#6B7280"}
    ]
    
    # Buscar leads para cada coluna
    kanban_data = []
    for column in columns:
        leads = await db.leads.find({
            "created_by": str(current_user["_id"]),
            "status": column["status"]
        }).sort("position", 1).to_list(1000)
        
        kanban_data.append({
            "status": column["status"],
            "title": column["title"],
            "color": column["color"],
            "leads": serialize_doc(leads)
        })
    
    return kanban_data

@app.post("/api/kanban/move")
async def move_lead(move_data: KanbanMove, current_user: dict = Depends(get_current_user)):
    try:
        # Atualizar o status e posição do lead
        result = await db.leads.update_one(
            {"_id": ObjectId(move_data.lead_id), "created_by": str(current_user["_id"])},
            {
                "$set": {
                    "status": move_data.new_status,
                    "position": move_data.new_position,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Buscar o lead atualizado
        updated_lead = await db.leads.find_one({"_id": ObjectId(move_data.lead_id)})
        
        # Log da atividade
        activity = {
            "user_id": str(current_user["_id"]),
            "lead_id": move_data.lead_id,
            "action": "moved",
            "details": f"Lead '{updated_lead['title']}' movido para {move_data.new_status}",
            "timestamp": datetime.utcnow()
        }
        await db.activities.insert_one(activity)
        
        return {"message": "Lead moved successfully"}
    except Exception as e:
        if "Lead not found" in str(e):
            raise e
        raise HTTPException(status_code=400, detail="Invalid lead ID")

# Rotas do Dashboard
@app.get("/api/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    
    # Total de leads
    total_leads = await db.leads.count_documents({"created_by": user_id})
    
    # Estatísticas por status
    pipeline = [
        {"$match": {"created_by": user_id}},
        {
            "$group": {
                "_id": "$status",
                "count": {"$sum": 1},
                "value": {"$sum": "$value"}
            }
        }
    ]
    status_stats_raw = await db.leads.aggregate(pipeline).to_list(1000)
    status_stats = {item["_id"]: {"count": item["count"], "value": item["value"]} for item in status_stats_raw}
    
    # Taxa de conversão
    fechados_ganhos = status_stats.get("fechado_ganho", {}).get("count", 0)
    conversion_rate = round((fechados_ganhos / total_leads * 100) if total_leads > 0 else 0, 1)
    
    # Ticket médio
    total_value = status_stats.get("fechado_ganho", {}).get("value", 0)
    avg_deal_size = total_value / fechados_ganhos if fechados_ganhos > 0 else 0
    
    # Top fontes
    pipeline_sources = [
        {"$match": {"created_by": user_id}},
        {
            "$group": {
                "_id": "$source",
                "count": {"$sum": 1},
                "total_value": {"$sum": "$value"}
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_sources = await db.leads.aggregate(pipeline_sources).to_list(5)
    
    # Atividades recentes
    recent_activities = await db.activities.find(
        {"user_id": user_id}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    return {
        "total_leads": total_leads,
        "conversion_rate": conversion_rate,
        "avg_deal_size": avg_deal_size,
        "status_stats": status_stats,
        "top_sources": top_sources,
        "recent_activities": serialize_doc(recent_activities)
    }

# Rotas do Calendário
@app.get("/api/calendar/events")
async def get_calendar_events(current_user: dict = Depends(get_current_user)):
    events = await db.calendar_events.find({
        "created_by": str(current_user["_id"])
    }).sort("start_time", 1).to_list(1000)
    return serialize_doc(events)

@app.post("/api/calendar/events")
async def create_calendar_event(event_data: CalendarEvent, current_user: dict = Depends(get_current_user)):
    event_doc = event_data.dict()
    event_doc["created_by"] = str(current_user["_id"])
    event_doc["created_at"] = datetime.utcnow()
    
    result = await db.calendar_events.insert_one(event_doc)
    event_doc["_id"] = result.inserted_id
    
    return serialize_doc(event_doc)

# Rota de conectar Google Calendar (placeholder)
@app.get("/api/auth/google/connect")
async def connect_google_calendar(current_user: dict = Depends(get_current_user)):
    # Esta é uma implementação placeholder
    # Em uma implementação real, você configuraria OAuth2 com Google
    return {
        "authorization_url": "https://accounts.google.com/oauth/authorize",
        "message": "Google Calendar integration not implemented yet"
    }

# Rota raiz
@app.get("/")
async def root():
    return {"message": "CRM Kanban API is running"}

@app.get("/api/")
async def api_root():
    return {"message": "CRM Kanban API v1.0.0", "status": "active"}

# Rota de health check
@app.get("/api/health")
async def health_check():
    try:
        # Testar conexão com o banco
        await client.admin.command('ping')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

