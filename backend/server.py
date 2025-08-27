from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import socketio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path
import os
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Union
import asyncio
from enum import Enum
import jwt
import bcrypt
from pydantic import BaseModel, Field, EmailStr, validator
import re

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'lms_database')]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key')
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', '30'))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRE_DAYS', '7'))
JWT_ALGORITHM = "HS256"

# Socket.IO setup
sio = socketio.AsyncServer(cors_allowed_origins="*", async_mode="asgi")
socket_app = socketio.ASGIApp(sio)

# FastAPI app
app = FastAPI(title="LMS CO/PO Assessment System", description="AI-powered Learning Management System")
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Enums
class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    TEACHER = "TEACHER" 
    STUDENT = "STUDENT"

class ExamStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    LIVE = "live"
    ENDED = "ended"
    GRADED = "graded"

class QuestionType(str, Enum):
    MCQ = "MCQ"
    MSQ = "MSQ"
    TRUE_FALSE = "TRUE_FALSE"
    NUMERIC = "NUMERIC"
    SHORT = "SHORT"
    DESCRIPTIVE = "DESCRIPTIVE"
    CODE = "CODE"

class AttemptStatus(str, Enum):
    NOT_STARTED = "not_started"
    ACTIVE = "active"
    SUBMITTED = "submitted"
    AUTO_SUBMITTED = "auto_submitted"
    FOR_REVIEW = "for_review"
    GRADED = "graded"
    INVALIDATED = "invalidated"

class BloomLevel(str, Enum):
    REMEMBER = "Remember"
    UNDERSTAND = "Understand"
    APPLY = "Apply"
    ANALYZE = "Analyze"
    EVALUATE = "Evaluate"
    CREATE = "Create"

class Difficulty(str, Enum):
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"

# Utility functions
def generate_uuid() -> str:
    return str(uuid.uuid4())

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None

# Dependencies
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    token = credentials.credentials
    payload = verify_token(token)
    if payload is None or payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    user = await db.users.find_one({"id": payload.get("user_id")})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

async def get_admin_user(current_user: Dict = Depends(get_current_user)) -> Dict:
    if current_user["role"] != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user

async def get_teacher_user(current_user: Dict = Depends(get_current_user)) -> Dict:
    if current_user["role"] not in [UserRole.SUPER_ADMIN, UserRole.TEACHER]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Teacher access required")
    return current_user

# Pydantic Models
class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    role: UserRole
    phone: Optional[str] = None
    dept_id: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def validate_password(cls, v):
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        return v

class User(UserBase):
    id: str = Field(default_factory=generate_uuid)
    hashed_password: str
    status: str = "active"
    last_login_at: Optional[datetime] = None
    mfa_enabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(UserBase):
    id: str
    status: str
    last_login_at: Optional[datetime]
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse

class Department(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    name: str = Field(..., min_length=2, max_length=100)
    code: str = Field(..., min_length=2, max_length=20)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Program(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    dept_id: str
    name: str = Field(..., min_length=2, max_length=100)
    code: str = Field(..., min_length=2, max_length=20)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Course(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    program_id: str
    name: str = Field(..., min_length=2, max_length=100)
    code: str = Field(..., min_length=2, max_length=20)
    semester: int = Field(..., ge=1, le=10)
    batch_year: int = Field(..., ge=2020)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Subject(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    course_id: str
    name: str = Field(..., min_length=2, max_length=100)
    code: str = Field(..., min_length=2, max_length=20)
    credits: float = Field(..., ge=0, le=10)
    teacher_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CO(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    subject_id: str
    code: str = Field(..., min_length=1, max_length=20)
    description: str = Field(..., min_length=10)
    bloom_level: BloomLevel
    target_level: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PO(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    program_id: str
    code: str = Field(..., min_length=1, max_length=20)
    description: str = Field(..., min_length=10)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class COPOMapping(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    co_id: str
    po_id: str
    weight: int = Field(..., ge=1, le=3)  # 1=low, 2=medium, 3=high
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Question(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    subject_id: str
    type: QuestionType
    text: str = Field(..., min_length=10)
    options: Optional[Dict[str, str]] = None  # For MCQ/MSQ: {"A": "option1", "B": "option2"}
    correct_key: Optional[Union[str, List[str], float]] = None  # MCQ: "A", MSQ: ["A","B"], NUMERIC: 42.5
    max_marks: float = Field(..., ge=0.1, le=100)
    co_id: str
    po_ids: List[str] = Field(default_factory=list)
    difficulty: Difficulty
    tags: List[str] = Field(default_factory=list)
    negative_marking: Optional[Dict] = None  # {"enabled": True, "penalty": 0.25}
    partial_scoring: Optional[Dict] = None  # For MSQ, NUMERIC
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Exam(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    subject_id: str
    title: str = Field(..., min_length=5)
    type: str = Field(default="quiz")  # quiz, midsem, endsem, assignment, practical
    duration_sec: int = Field(..., ge=300)  # minimum 5 minutes
    join_window_sec: int = Field(default=300)  # 5 minutes default
    total_marks: float = Field(..., ge=1)
    negative_marking_default: Optional[Dict] = None
    randomized: str = Field(default="none")  # none, question_order, option_order, both
    reentry_policy: str = Field(default="block")  # block, allow_once, allow_multiple
    created_by: str
    status: ExamStatus = ExamStatus.DRAFT
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ExamQuestion(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    exam_id: str
    question_id: str
    marks_override: Optional[float] = None
    order_index: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ExamSession(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    exam_id: str
    status: str = "scheduled"  # scheduled, live, ended
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StudentExamAttempt(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    session_id: str
    student_id: str
    status: AttemptStatus = AttemptStatus.NOT_STARTED
    joined_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    total_score: Optional[float] = None
    ai_scored_at: Optional[datetime] = None
    malpractice_risk: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Response(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    attempt_id: str
    question_id: str
    answer_payload: Dict  # Student's answer in various formats
    autosave_ts: Optional[datetime] = None
    final_submit_ts: Optional[datetime] = None
    client_latency_ms: Optional[int] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Score(BaseModel):
    id: str = Field(default_factory=generate_uuid)
    response_id: str
    ai_score: Optional[float] = None
    human_score: Optional[float] = None
    final_score: float = 0.0
    scorer_type: str = "rule"  # rule, ai, human, hybrid
    explanation: Optional[str] = None
    confidence: Optional[float] = None
    version: int = 1
    overridden_by: Optional[str] = None
    overridden_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# First-run setup models
class SetupStatus(BaseModel):
    id: str = Field(default="setup")
    is_setup_complete: bool = False
    setup_step: int = 0  # 0=not started, 1=admin created, 2=departments, 3=programs, etc.
    admin_id: Optional[str] = None
    institute_name: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SetupRequest(BaseModel):
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)
    admin_name: str = Field(..., min_length=2)
    institute_name: str = Field(..., min_length=2)

# API Routes

# Setup and Authentication Routes
@api_router.get("/setup/status")
async def get_setup_status():
    """Check if the system has been set up"""
    setup = await db.setup.find_one({"id": "setup"})
    if not setup:
        return {"is_setup_complete": False, "setup_step": 0}
    return {"is_setup_complete": setup.get("is_setup_complete", False), "setup_step": setup.get("setup_step", 0)}

@api_router.post("/setup/initialize")
async def initialize_system(setup_data: SetupRequest):
    """Initialize the system with first admin user"""
    # Check if already setup
    setup = await db.setup.find_one({"id": "setup"})
    if setup and setup.get("is_setup_complete"):
        raise HTTPException(status_code=400, detail="System already initialized")
    
    # Check if admin user already exists
    existing_admin = await db.users.find_one({"email": setup_data.admin_email})
    if existing_admin:
        raise HTTPException(status_code=400, detail="Admin user already exists")
    
    # Create admin user
    admin_user = User(
        name=setup_data.admin_name,
        email=setup_data.admin_email,
        role=UserRole.SUPER_ADMIN,
        hashed_password=hash_password(setup_data.admin_password)
    )
    
    await db.users.insert_one(admin_user.dict())
    
    # Update setup status
    setup_status = SetupStatus(
        is_setup_complete=True,
        setup_step=1,
        admin_id=admin_user.id,
        institute_name=setup_data.institute_name
    )
    
    await db.setup.replace_one({"id": "setup"}, setup_status.dict(), upsert=True)
    
    # Create access tokens
    access_token = create_access_token({"user_id": admin_user.id, "role": admin_user.role})
    refresh_token = create_refresh_token({"user_id": admin_user.id})
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(**admin_user.dict())
    )

@api_router.post("/auth/login", response_model=LoginResponse)
async def login(login_data: LoginRequest):
    """Authenticate user and return tokens"""
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Update last login
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"last_login_at": datetime.now(timezone.utc)}}
    )
    
    access_token = create_access_token({"user_id": user["id"], "role": user["role"]})
    refresh_token = create_refresh_token({"user_id": user["id"]})
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(**user)
    )

@api_router.post("/auth/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    payload = verify_token(refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user = await db.users.find_one({"id": payload.get("user_id")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    access_token = create_access_token({"user_id": user["id"], "role": user["role"]})
    new_refresh_token = create_refresh_token({"user_id": user["id"]})
    
    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

# User Management Routes
@api_router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information"""
    return UserResponse(**current_user)

@api_router.get("/users", response_model=List[UserResponse])
async def list_users(current_user: Dict = Depends(get_admin_user)):
    """List all users (admin only)"""
    users = await db.users.find().to_list(1000)
    return [UserResponse(**user) for user in users]

@api_router.post("/users", response_model=UserResponse)
async def create_user(user_data: UserCreate, current_user: Dict = Depends(get_admin_user)):
    """Create a new user (admin only)"""
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")
    
    new_user = User(**user_data.dict(), hashed_password=hash_password(user_data.password))
    await db.users.insert_one(new_user.dict())
    
    return UserResponse(**new_user.dict())

# Department Management Routes
@api_router.get("/departments", response_model=List[Department])
async def list_departments(current_user: Dict = Depends(get_current_user)):
    """List all departments"""
    departments = await db.departments.find().to_list(1000)
    return [Department(**dept) for dept in departments]

@api_router.post("/departments", response_model=Department)
async def create_department(dept_data: Department, current_user: Dict = Depends(get_admin_user)):
    """Create a new department (admin only)"""
    # Check for duplicate code
    existing_dept = await db.departments.find_one({"code": dept_data.code})
    if existing_dept:
        raise HTTPException(status_code=400, detail="Department code already exists")
    
    await db.departments.insert_one(dept_data.dict())
    return dept_data

# Program Management Routes
@api_router.get("/programs", response_model=List[Program])
async def list_programs(dept_id: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    """List programs, optionally filtered by department"""
    query = {"dept_id": dept_id} if dept_id else {}
    programs = await db.programs.find(query).to_list(1000)
    return [Program(**prog) for prog in programs]

@api_router.post("/programs", response_model=Program)
async def create_program(prog_data: Program, current_user: Dict = Depends(get_admin_user)):
    """Create a new program (admin only)"""
    # Check for duplicate code
    existing_prog = await db.programs.find_one({"code": prog_data.code})
    if existing_prog:
        raise HTTPException(status_code=400, detail="Program code already exists")
    
    # Verify department exists
    dept = await db.departments.find_one({"id": prog_data.dept_id})
    if not dept:
        raise HTTPException(status_code=400, detail="Department not found")
    
    await db.programs.insert_one(prog_data.dict())
    return prog_data

# Health check
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@api_router.get("/")
async def root():
    """Root endpoint"""
    return {"message": "LMS CO/PO Assessment System API", "version": "1.0.0"}

# WebSocket Events
@sio.event
async def connect(sid, environ, auth):
    """Handle client connection"""
    logger.info(f"Client {sid} connected")

@sio.event
async def disconnect(sid):
    """Handle client disconnection"""
    logger.info(f"Client {sid} disconnected")

@sio.event
async def join_exam_room(sid, data):
    """Handle joining exam room"""
    exam_id = data.get('exam_id')
    user_id = data.get('user_id')
    
    if exam_id and user_id:
        await sio.enter_room(sid, f"exam_{exam_id}")
        logger.info(f"User {user_id} joined exam room {exam_id}")

@sio.event
async def leave_exam_room(sid, data):
    """Handle leaving exam room"""
    exam_id = data.get('exam_id')
    if exam_id:
        await sio.leave_room(sid, f"exam_{exam_id}")

# Include router in app
app.include_router(api_router)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Socket.IO app
app.mount("/socket.io", socket_app)

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database indexes and setup"""
    logger.info("Starting up LMS system...")
    
    # Create indexes for better performance
    await db.users.create_index("email", unique=True)
    await db.departments.create_index("code", unique=True)
    await db.programs.create_index("code", unique=True)
    await db.courses.create_index([("program_id", 1), ("code", 1)], unique=True)
    await db.subjects.create_index([("course_id", 1), ("code", 1)], unique=True)
    await db.cos.create_index([("subject_id", 1), ("code", 1)], unique=True)
    await db.pos.create_index([("program_id", 1), ("code", 1)], unique=True)
    
    logger.info("Database indexes created")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources"""
    client.close()
    logger.info("LMS system shutdown complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8001, reload=True)