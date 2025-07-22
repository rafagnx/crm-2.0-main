from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
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
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="CRM Kanban API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24 * 7  # 7 days

# Google Calendar Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/calendar']

security = HTTPBearer()

# Enums
class UserRole(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"

class LeadStatus(str, Enum):
    NEW = "novo"
    QUALIFIED = "qualificado"
    PROPOSAL = "proposta"
    NEGOTIATION = "negociacao"
    CLOSED_WON = "fechado_ganho"
    CLOSED_LOST = "fechado_perdido"

class EventType(str, Enum):
    FOLLOW_UP = "follow_up"
    MEETING = "meeting"
    CALL = "call"
    DEMO = "demo"

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    password_hash: str
    role: UserRole = UserRole.USER
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    google_tokens: Optional[Dict] = None

class UserCreate(BaseModel):
    email: str
    name: str
    password: str
    role: UserRole = UserRole.USER

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: UserRole
    created_at: datetime
    is_active: bool

class Lead(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    company: str = ""
    contact_name: str = ""
    email: str = ""
    phone: str = ""
    status: LeadStatus = LeadStatus.NEW
    tags: List[str] = []
    notes: str = ""
    value: float = 0.0
    priority: str = "medium"  # low, medium, high
    assigned_to: str = ""  # User ID
    created_by: str = ""   # User ID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    position: int = 0  # For drag & drop ordering
    next_follow_up: Optional[datetime] = None
    expected_close_date: Optional[datetime] = None
    source: str = ""  # website, referral, cold_call, etc.

class LeadCreate(BaseModel):
    title: str
    company: str = ""
    contact_name: str = ""
    email: str = ""
    phone: str = ""
    status: LeadStatus = LeadStatus.NEW
    tags: List[str] = []
    notes: str = ""
    value: float = 0.0
    priority: str = "medium"
    assigned_to: str = ""
    next_follow_up: Optional[datetime] = None
    expected_close_date: Optional[datetime] = None
    source: str = ""

class LeadUpdate(BaseModel):
    title: Optional[str] = None
    company: Optional[str] = None
    contact_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[LeadStatus] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    value: Optional[float] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    position: Optional[int] = None
    next_follow_up: Optional[datetime] = None
    expected_close_date: Optional[datetime] = None
    source: Optional[str] = None

class Activity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    lead_id: str
    user_id: str
    action: str
    details: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AutomationRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    trigger_status: LeadStatus
    action: str  # create_task, send_email, schedule_follow_up
    action_params: Dict = {}
    created_by: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AutomationRuleCreate(BaseModel):
    name: str
    trigger_status: LeadStatus
    action: str
    action_params: Dict = {}

class CalendarEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    lead_id: str
    user_id: str
    title: str
    description: str = ""
    start_time: datetime
    end_time: datetime
    event_type: EventType
    google_event_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class CalendarEventCreate(BaseModel):
    lead_id: str
    title: str
    description: str = ""
    start_time: datetime
    end_time: datetime
    event_type: EventType

class KanbanColumn(BaseModel):
    status: LeadStatus
    title: str
    color: str
    leads: List[Lead] = []

# Authentication helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt_token(credentials.credentials)
    user = await db.users.find_one({"id": payload["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

# Google Calendar helpers
async def get_google_calendar_service(user: User):
    if not user.google_tokens:
        return None
    
    creds = Credentials(
        token=user.google_tokens.get('access_token'),
        refresh_token=user.google_tokens.get('refresh_token'),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=GOOGLE_SCOPES
    )
    
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        # Update tokens in database
        await db.users.update_one(
            {"id": user.id},
            {"$set": {"google_tokens": {
                "access_token": creds.token,
                "refresh_token": creds.refresh_token
            }}}
        )
    
    return build('calendar', 'v3', credentials=creds)

async def create_google_event(service, event_data: CalendarEvent):
    event = {
        'summary': event_data.title,
        'description': event_data.description,
        'start': {
            'dateTime': event_data.start_time.isoformat(),
            'timeZone': 'America/Sao_Paulo',
        },
        'end': {
            'dateTime': event_data.end_time.isoformat(),
            'timeZone': 'America/Sao_Paulo',
        },
    }
    
    try:
        result = service.events().insert(calendarId='primary', body=event).execute()
        return result.get('id')
    except Exception as e:
        logging.error(f"Error creating Google Calendar event: {e}")
        return None

# Automation helpers
async def process_automation_rules(lead_id: str, new_status: LeadStatus, user_id: str):
    """Process automation rules when a lead changes status"""
    rules = await db.automation_rules.find({"trigger_status": new_status, "is_active": True}).to_list(100)
    
    for rule_data in rules:
        rule = AutomationRule(**rule_data)
        
        if rule.action == "schedule_follow_up":
            # Schedule automatic follow-up
            follow_up_date = datetime.utcnow() + timedelta(days=rule.action_params.get('days', 3))
            await db.leads.update_one(
                {"id": lead_id},
                {"$set": {"next_follow_up": follow_up_date}}
            )
            
            # Log activity
            activity = Activity(
                lead_id=lead_id,
                user_id=user_id,
                action="automated_follow_up_scheduled",
                details=f"Follow-up automatically scheduled for {follow_up_date.strftime('%Y-%m-%d')}"
            )
            await db.activities.insert_one(activity.dict())
        
        elif rule.action == "create_task":
            # Create a task/activity
            activity = Activity(
                lead_id=lead_id,
                user_id=user_id,
                action="automated_task_created",
                details=rule.action_params.get('task_description', 'Automated task created')
            )
            await db.activities.insert_one(activity.dict())

# Authentication Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = hash_password(user_data.password)
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=hashed_password,
        role=user_data.role
    )
    
    await db.users.insert_one(user.dict())
    
    # Create JWT token
    token = create_jwt_token(user.id, user.email, user.role.value)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user.dict())
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    # Find user
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user["is_active"]:
        raise HTTPException(status_code=401, detail="Account deactivated")
    
    # Create JWT token
    token = create_jwt_token(user["id"], user["email"], user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user)
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

# Google Calendar OAuth Routes
@api_router.get("/auth/google/connect")
async def connect_google_calendar(current_user: User = Depends(get_current_user)):
    """Initiate Google Calendar OAuth flow"""
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES
    )
    
    flow.redirect_uri = f"https://89088de9-de4f-40fb-b5f4-8abb04375e5b.preview.emergentagent.com/api/auth/google/callback"
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        state=current_user.id
    )
    
    return {"authorization_url": authorization_url}

@api_router.get("/auth/google/callback")
async def google_calendar_callback(code: str, state: str):
    """Handle Google Calendar OAuth callback"""
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES
    )
    
    flow.redirect_uri = f"https://89088de9-de4f-40fb-b5f4-8abb04375e5b.preview.emergentagent.com/api/auth/google/callback"
    flow.fetch_token(code=code)
    
    credentials = flow.credentials
    
    # Save tokens to user
    await db.users.update_one(
        {"id": state},
        {"$set": {"google_tokens": {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token
        }}}
    )
    
    return {"message": "Google Calendar connected successfully"}

# User Routes
@api_router.get("/users", response_model=List[UserResponse])
async def get_users(current_user: User = Depends(get_current_user)):
    users = await db.users.find({"is_active": True}).to_list(1000)
    return [UserResponse(**user) for user in users]

# Lead Routes
@api_router.post("/leads", response_model=Lead)
async def create_lead(lead_data: LeadCreate, current_user: User = Depends(get_current_user)):
    lead = Lead(**lead_data.dict(), created_by=current_user.id)
    
    # Get max position for the status
    max_position = await db.leads.find_one(
        {"status": lead.status}, 
        sort=[("position", -1)]
    )
    if max_position:
        lead.position = max_position["position"] + 1
    
    await db.leads.insert_one(lead.dict())
    
    # Log activity
    activity = Activity(
        lead_id=lead.id,
        user_id=current_user.id,
        action="created",
        details=f"Lead '{lead.title}' created"
    )
    await db.activities.insert_one(activity.dict())
    
    # Process automation rules
    await process_automation_rules(lead.id, lead.status, current_user.id)
    
    return lead

@api_router.get("/leads", response_model=List[Lead])
async def get_leads(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    priority: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = {}
    if status:
        query["status"] = status
    if assigned_to:
        query["assigned_to"] = assigned_to
    if priority:
        query["priority"] = priority
    
    leads = await db.leads.find(query).sort("position", 1).to_list(1000)
    return [Lead(**lead) for lead in leads]

@api_router.get("/leads/{lead_id}", response_model=Lead)
async def get_lead(lead_id: str, current_user: User = Depends(get_current_user)):
    lead = await db.leads.find_one({"id": lead_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    return Lead(**lead)

@api_router.put("/leads/{lead_id}", response_model=Lead)
async def update_lead(
    lead_id: str, 
    lead_update: LeadUpdate, 
    current_user: User = Depends(get_current_user)
):
    lead = await db.leads.find_one({"id": lead_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    # Update fields
    update_data = {k: v for k, v in lead_update.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    old_status = lead["status"]
    new_status = update_data.get("status", old_status)
    
    await db.leads.update_one(
        {"id": lead_id},
        {"$set": update_data}
    )
    
    # Get updated lead
    updated_lead = await db.leads.find_one({"id": lead_id})
    
    # Log activity
    activity = Activity(
        lead_id=lead_id,
        user_id=current_user.id,
        action="updated",
        details=f"Lead updated"
    )
    await db.activities.insert_one(activity.dict())
    
    # Process automation rules if status changed
    if old_status != new_status:
        await process_automation_rules(lead_id, new_status, current_user.id)
    
    return Lead(**updated_lead)

@api_router.delete("/leads/{lead_id}")
async def delete_lead(lead_id: str, current_user: User = Depends(get_current_user)):
    result = await db.leads.delete_one({"id": lead_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    # Log activity
    activity = Activity(
        lead_id=lead_id,
        user_id=current_user.id,
        action="deleted",
        details=f"Lead deleted"
    )
    await db.activities.insert_one(activity.dict())
    
    return {"message": "Lead deleted successfully"}

# Kanban Board Routes
@api_router.get("/kanban", response_model=List[KanbanColumn])
async def get_kanban_board(current_user: User = Depends(get_current_user)):
    # Define column structure
    columns = [
        {"status": LeadStatus.NEW, "title": "Novo", "color": "#3B82F6"},
        {"status": LeadStatus.QUALIFIED, "title": "Qualificado", "color": "#10B981"},
        {"status": LeadStatus.PROPOSAL, "title": "Proposta", "color": "#F59E0B"},
        {"status": LeadStatus.NEGOTIATION, "title": "Negociação", "color": "#EF4444"},
        {"status": LeadStatus.CLOSED_WON, "title": "Fechado (Ganho)", "color": "#059669"},
        {"status": LeadStatus.CLOSED_LOST, "title": "Fechado (Perdido)", "color": "#6B7280"}
    ]
    
    kanban_columns = []
    for column in columns:
        leads = await db.leads.find({"status": column["status"]}).sort("position", 1).to_list(1000)
        kanban_columns.append(KanbanColumn(
            status=column["status"],
            title=column["title"],
            color=column["color"],
            leads=[Lead(**lead) for lead in leads]
        ))
    
    return kanban_columns

@api_router.post("/kanban/move")
async def move_lead(
    data: Dict,
    current_user: User = Depends(get_current_user)
):
    lead_id = data.get("lead_id")
    new_status = data.get("new_status")
    new_position = data.get("new_position", 0)
    
    if not lead_id or not new_status:
        raise HTTPException(status_code=400, detail="lead_id and new_status are required")
    
    # Get old status for automation
    lead = await db.leads.find_one({"id": lead_id})
    old_status = lead["status"] if lead else None
    
    # Update lead status and position
    await db.leads.update_one(
        {"id": lead_id},
        {"$set": {"status": new_status, "position": new_position, "updated_at": datetime.utcnow()}}
    )
    
    # Log activity
    activity = Activity(
        lead_id=lead_id,
        user_id=current_user.id,
        action="moved",
        details=f"Lead moved to {new_status}"
    )
    await db.activities.insert_one(activity.dict())
    
    # Process automation rules if status changed
    if old_status != new_status:
        await process_automation_rules(lead_id, new_status, current_user.id)
    
    return {"message": "Lead moved successfully"}

# Calendar Routes
@api_router.post("/calendar/events", response_model=CalendarEvent)
async def create_calendar_event(
    event_data: CalendarEventCreate, 
    current_user: User = Depends(get_current_user)
):
    event = CalendarEvent(**event_data.dict(), user_id=current_user.id)
    
    # Try to create Google Calendar event
    service = await get_google_calendar_service(current_user)
    if service:
        google_event_id = await create_google_event(service, event)
        event.google_event_id = google_event_id
    
    await db.calendar_events.insert_one(event.dict())
    
    # Log activity
    activity = Activity(
        lead_id=event.lead_id,
        user_id=current_user.id,
        action="event_created",
        details=f"Calendar event '{event.title}' scheduled for {event.start_time.strftime('%Y-%m-%d %H:%M')}"
    )
    await db.activities.insert_one(activity.dict())
    
    return event

@api_router.get("/calendar/events", response_model=List[CalendarEvent])
async def get_calendar_events(current_user: User = Depends(get_current_user)):
    events = await db.calendar_events.find({"user_id": current_user.id}).sort("start_time", 1).to_list(1000)
    return [CalendarEvent(**event) for event in events]

# Automation Routes
@api_router.post("/automation/rules", response_model=AutomationRule)
async def create_automation_rule(
    rule_data: AutomationRuleCreate,
    current_user: User = Depends(get_current_user)
):
    rule = AutomationRule(**rule_data.dict(), created_by=current_user.id)
    await db.automation_rules.insert_one(rule.dict())
    return rule

@api_router.get("/automation/rules", response_model=List[AutomationRule])
async def get_automation_rules(current_user: User = Depends(get_current_user)):
    rules = await db.automation_rules.find({"created_by": current_user.id}).to_list(1000)
    return [AutomationRule(**rule) for rule in rules]

# Activity Routes
@api_router.get("/leads/{lead_id}/activities", response_model=List[Activity])
async def get_lead_activities(lead_id: str, current_user: User = Depends(get_current_user)):
    activities = await db.activities.find({"lead_id": lead_id}).sort("timestamp", -1).to_list(1000)
    return [Activity(**activity) for activity in activities]

# Advanced Dashboard/Stats Routes
@api_router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    # Count leads by status
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}, "total_value": {"$sum": "$value"}}}
    ]
    status_stats = await db.leads.aggregate(pipeline).to_list(None)
    
    # Conversion rates
    total_leads = await db.leads.count_documents({})
    closed_won = await db.leads.count_documents({"status": LeadStatus.CLOSED_WON})
    closed_lost = await db.leads.count_documents({"status": LeadStatus.CLOSED_LOST})
    
    conversion_rate = (closed_won / total_leads * 100) if total_leads > 0 else 0
    
    # Average deal size
    won_deals = await db.leads.find({"status": LeadStatus.CLOSED_WON}).to_list(None)
    avg_deal_size = sum(deal.get("value", 0) for deal in won_deals) / len(won_deals) if won_deals else 0
    
    # Recent activities
    recent_activities = await db.activities.find().sort("timestamp", -1).limit(10).to_list(10)
    
    # Monthly trends (last 6 months)
    from datetime import datetime, timedelta
    six_months_ago = datetime.utcnow() - timedelta(days=180)
    monthly_pipeline = [
        {"$match": {"created_at": {"$gte": six_months_ago}}},
        {"$group": {
            "_id": {
                "year": {"$year": "$created_at"},
                "month": {"$month": "$created_at"}
            },
            "leads_created": {"$sum": 1},
            "total_value": {"$sum": "$value"}
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1}}
    ]
    monthly_trends = await db.leads.aggregate(monthly_pipeline).to_list(None)
    
    # Top performing sources
    source_pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}, "total_value": {"$sum": "$value"}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_sources = await db.leads.aggregate(source_pipeline).to_list(None)
    
    return {
        "status_stats": {item["_id"]: {"count": item["count"], "value": item["total_value"]} for item in status_stats},
        "total_leads": total_leads,
        "conversion_rate": round(conversion_rate, 2),
        "avg_deal_size": round(avg_deal_size, 2),
        "recent_activities": [Activity(**activity) for activity in recent_activities],
        "monthly_trends": monthly_trends,
        "top_sources": top_sources
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

    # ... outras importações e configurações ...

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", # Para desenvolvimento local
        "https://crm-2-0-main.vercel.app" # <--- ADICIONE AQUI A URL DO SEU FRONTEND NO VERCEL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ... restante do seu código FastAPI ...