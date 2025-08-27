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
@api_router.post("/setup/reset")
async def reset_setup():
    """Reset setup status (for development)"""
    await db.setup.delete_many({})
    await db.users.delete_many({})
    return {"message": "Setup reset successfully"}

@api_router.get("/setup/status")
async def get_setup_status():
    """Check if the system has been set up"""
    setup = await db.setup.find_one({"id": "setup"})
    if not setup:
        return {"is_setup_complete": False, "setup_step": 0}
    
    # Double check if admin user actually exists
    admin_exists = await db.users.find_one({"role": UserRole.SUPER_ADMIN})
    if not admin_exists:
        # Reset setup if no admin found
        await db.setup.delete_one({"id": "setup"})
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

# Course Management Routes
@api_router.get("/courses", response_model=List[Course])
async def list_courses(program_id: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    """List courses, optionally filtered by program"""
    query = {"program_id": program_id} if program_id else {}
    courses = await db.courses.find(query).to_list(1000)
    return [Course(**course) for course in courses]

@api_router.post("/courses", response_model=Course)
async def create_course(course_data: Course, current_user: Dict = Depends(get_admin_user)):
    """Create a new course (admin only)"""
    # Check for duplicate code within the same program
    existing_course = await db.courses.find_one({
        "program_id": course_data.program_id,
        "code": course_data.code
    })
    if existing_course:
        raise HTTPException(status_code=400, detail="Course code already exists in this program")
    
    # Verify program exists
    program = await db.programs.find_one({"id": course_data.program_id})
    if not program:
        raise HTTPException(status_code=400, detail="Program not found")
    
    await db.courses.insert_one(course_data.dict())
    return course_data

@api_router.get("/courses/{course_id}", response_model=Course)
async def get_course(course_id: str, current_user: Dict = Depends(get_current_user)):
    """Get course by ID"""
    course = await db.courses.find_one({"id": course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return Course(**course)

# Subject Management Routes
@api_router.get("/subjects", response_model=List[Subject])
async def list_subjects(course_id: Optional[str] = None, teacher_id: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    """List subjects, optionally filtered by course or teacher"""
    query = {}
    if course_id:
        query["course_id"] = course_id
    if teacher_id:
        query["teacher_id"] = teacher_id
    
    subjects = await db.subjects.find(query).to_list(1000)
    return [Subject(**subject) for subject in subjects]

@api_router.post("/subjects", response_model=Subject)
async def create_subject(subject_data: Subject, current_user: Dict = Depends(get_admin_user)):
    """Create a new subject (admin only)"""
    # Check for duplicate code within the same course
    existing_subject = await db.subjects.find_one({
        "course_id": subject_data.course_id,
        "code": subject_data.code
    })
    if existing_subject:
        raise HTTPException(status_code=400, detail="Subject code already exists in this course")
    
    # Verify course exists
    course = await db.courses.find_one({"id": subject_data.course_id})
    if not course:
        raise HTTPException(status_code=400, detail="Course not found")
    
    # Verify teacher exists and has TEACHER role
    teacher = await db.users.find_one({
        "id": subject_data.teacher_id,
        "role": {"$in": [UserRole.TEACHER, UserRole.SUPER_ADMIN]}
    })
    if not teacher:
        raise HTTPException(status_code=400, detail="Teacher not found or invalid role")
    
    await db.subjects.insert_one(subject_data.dict())
    return subject_data

@api_router.get("/subjects/{subject_id}", response_model=Subject)
async def get_subject(subject_id: str, current_user: Dict = Depends(get_current_user)):
    """Get subject by ID"""
    subject = await db.subjects.find_one({"id": subject_id})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    return Subject(**subject)

# CO Management Routes
@api_router.get("/subjects/{subject_id}/cos", response_model=List[CO])
async def list_subject_cos(subject_id: str, current_user: Dict = Depends(get_current_user)):
    """List all COs for a subject"""
    # Verify subject exists and user has access
    subject = await db.subjects.find_one({"id": subject_id})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    # Check if user is admin, teacher of this subject, or student enrolled
    if (current_user["role"] not in [UserRole.SUPER_ADMIN, UserRole.TEACHER] and 
        subject["teacher_id"] != current_user["id"]):
        # For students, we might want to check enrollment later
        pass
    
    cos = await db.cos.find({"subject_id": subject_id}).to_list(1000)
    return [CO(**co) for co in cos]

@api_router.post("/subjects/{subject_id}/cos", response_model=CO)
async def create_co(subject_id: str, co_data: CO, current_user: Dict = Depends(get_teacher_user)):
    """Create a new CO for a subject (teacher/admin only)"""
    # Verify subject exists
    subject = await db.subjects.find_one({"id": subject_id})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    # Check if user is admin or teacher of this subject
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied. You can only manage COs for your own subjects")
    
    # Check for duplicate CO code within the same subject
    existing_co = await db.cos.find_one({
        "subject_id": subject_id,
        "code": co_data.code
    })
    if existing_co:
        raise HTTPException(status_code=400, detail="CO code already exists in this subject")
    
    # Set the subject_id
    co_data.subject_id = subject_id
    await db.cos.insert_one(co_data.dict())
    return co_data

@api_router.put("/cos/{co_id}", response_model=CO)
async def update_co(co_id: str, co_data: CO, current_user: Dict = Depends(get_teacher_user)):
    """Update a CO (teacher/admin only)"""
    # Verify CO exists
    existing_co = await db.cos.find_one({"id": co_id})
    if not existing_co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    # Verify subject exists and user has access
    subject = await db.subjects.find_one({"id": existing_co["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check for duplicate CO code if code is being changed
    if co_data.code != existing_co["code"]:
        duplicate_co = await db.cos.find_one({
            "subject_id": existing_co["subject_id"],
            "code": co_data.code,
            "id": {"$ne": co_id}
        })
        if duplicate_co:
            raise HTTPException(status_code=400, detail="CO code already exists in this subject")
    
    # Update CO
    co_data.subject_id = existing_co["subject_id"]
    co_data.id = co_id
    co_data.updated_at = datetime.now(timezone.utc)
    
    await db.cos.replace_one({"id": co_id}, co_data.dict())
    return co_data

@api_router.delete("/cos/{co_id}")
async def delete_co(co_id: str, current_user: Dict = Depends(get_teacher_user)):
    """Delete a CO (teacher/admin only)"""
    # Verify CO exists
    existing_co = await db.cos.find_one({"id": co_id})
    if not existing_co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    # Verify subject exists and user has access
    subject = await db.subjects.find_one({"id": existing_co["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if CO is being used in questions or mappings
    questions_count = await db.questions.count_documents({"co_id": co_id})
    mappings_count = await db.co_po_mappings.count_documents({"co_id": co_id})
    
    if questions_count > 0 or mappings_count > 0:
        raise HTTPException(status_code=400, detail="Cannot delete CO. It is being used in questions or PO mappings")
    
    await db.cos.delete_one({"id": co_id})
    return {"message": "CO deleted successfully"}

# PO Management Routes
@api_router.get("/programs/{program_id}/pos", response_model=List[PO])
async def list_program_pos(program_id: str, current_user: Dict = Depends(get_current_user)):
    """List all POs for a program"""
    # Verify program exists
    program = await db.programs.find_one({"id": program_id})
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    pos = await db.pos.find({"program_id": program_id}).to_list(1000)
    return [PO(**po) for po in pos]

@api_router.post("/programs/{program_id}/pos", response_model=PO)
async def create_po(program_id: str, po_data: PO, current_user: Dict = Depends(get_admin_user)):
    """Create a new PO for a program (admin only)"""
    # Verify program exists
    program = await db.programs.find_one({"id": program_id})
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    # Check for duplicate PO code within the same program
    existing_po = await db.pos.find_one({
        "program_id": program_id,
        "code": po_data.code
    })
    if existing_po:
        raise HTTPException(status_code=400, detail="PO code already exists in this program")
    
    # Set the program_id
    po_data.program_id = program_id
    await db.pos.insert_one(po_data.dict())
    return po_data

# CO-PO Mapping Routes
@api_router.get("/cos/{co_id}/po-mappings", response_model=List[COPOMapping])
async def list_co_po_mappings(co_id: str, current_user: Dict = Depends(get_current_user)):
    """List all PO mappings for a CO"""
    # Verify CO exists
    co = await db.cos.find_one({"id": co_id})
    if not co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    mappings = await db.co_po_mappings.find({"co_id": co_id}).to_list(1000)
    return [COPOMapping(**mapping) for mapping in mappings]

@api_router.post("/cos/{co_id}/po-mappings", response_model=COPOMapping)
async def create_co_po_mapping(co_id: str, mapping_data: COPOMapping, current_user: Dict = Depends(get_teacher_user)):
    """Create CO-PO mapping (teacher/admin only)"""
    # Verify CO exists and user has access
    co = await db.cos.find_one({"id": co_id})
    if not co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    # Verify subject and user access
    subject = await db.subjects.find_one({"id": co["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Verify PO exists
    po = await db.pos.find_one({"id": mapping_data.po_id})
    if not po:
        raise HTTPException(status_code=404, detail="PO not found")
    
    # Check for duplicate mapping
    existing_mapping = await db.co_po_mappings.find_one({
        "co_id": co_id,
        "po_id": mapping_data.po_id
    })
    if existing_mapping:
        raise HTTPException(status_code=400, detail="CO-PO mapping already exists")
    
    # Set the co_id
    mapping_data.co_id = co_id
    await db.co_po_mappings.insert_one(mapping_data.dict())
    return mapping_data

@api_router.put("/co-po-mappings/{mapping_id}", response_model=COPOMapping)
async def update_co_po_mapping(mapping_id: str, mapping_data: COPOMapping, current_user: Dict = Depends(get_teacher_user)):
    """Update CO-PO mapping weight (teacher/admin only)"""
    # Verify mapping exists
    existing_mapping = await db.co_po_mappings.find_one({"id": mapping_id})
    if not existing_mapping:
        raise HTTPException(status_code=404, detail="CO-PO mapping not found")
    
    # Verify CO and subject access
    co = await db.cos.find_one({"id": existing_mapping["co_id"]})
    if not co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    subject = await db.subjects.find_one({"id": co["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update only the weight
    await db.co_po_mappings.update_one(
        {"id": mapping_id},
        {"$set": {"weight": mapping_data.weight}}
    )
    
    updated_mapping = await db.co_po_mappings.find_one({"id": mapping_id})
    return COPOMapping(**updated_mapping)

@api_router.delete("/co-po-mappings/{mapping_id}")
async def delete_co_po_mapping(mapping_id: str, current_user: Dict = Depends(get_teacher_user)):
    """Delete CO-PO mapping (teacher/admin only)"""
    # Verify mapping exists
    existing_mapping = await db.co_po_mappings.find_one({"id": mapping_id})
    if not existing_mapping:
        raise HTTPException(status_code=404, detail="CO-PO mapping not found")
    
    # Verify CO and subject access
    co = await db.cos.find_one({"id": existing_mapping["co_id"]})
    if not co:
        raise HTTPException(status_code=404, detail="CO not found")
    
    subject = await db.subjects.find_one({"id": co["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.co_po_mappings.delete_one({"id": mapping_id})
    return {"message": "CO-PO mapping deleted successfully"}

# Question Bank Routes
@api_router.get("/subjects/{subject_id}/questions", response_model=List[Question])
async def list_subject_questions(
    subject_id: str, 
    type: Optional[QuestionType] = None,
    difficulty: Optional[Difficulty] = None,
    co_id: Optional[str] = None,
    tags: Optional[str] = None,
    current_user: Dict = Depends(get_teacher_user)
):
    """List questions for a subject with optional filters"""
    # Verify subject exists and user has access
    subject = await db.subjects.find_one({"id": subject_id})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build query
    query = {"subject_id": subject_id}
    if type:
        query["type"] = type
    if difficulty:
        query["difficulty"] = difficulty
    if co_id:
        query["co_id"] = co_id
    if tags:
        tag_list = [tag.strip() for tag in tags.split(",")]
        query["tags"] = {"$in": tag_list}
    
    questions = await db.questions.find(query).to_list(1000)
    return [Question(**question) for question in questions]

@api_router.post("/subjects/{subject_id}/questions", response_model=Question)
async def create_question(subject_id: str, question_data: Question, current_user: Dict = Depends(get_teacher_user)):
    """Create a new question (teacher/admin only)"""
    # Verify subject exists and user has access
    subject = await db.subjects.find_one({"id": subject_id})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Verify CO exists and belongs to this subject
    co = await db.cos.find_one({"id": question_data.co_id, "subject_id": subject_id})
    if not co:
        raise HTTPException(status_code=400, detail="CO not found in this subject")
    
    # Validate question type-specific requirements
    if question_data.type in [QuestionType.MCQ, QuestionType.MSQ, QuestionType.TRUE_FALSE]:
        if not question_data.options or not question_data.correct_key:
            raise HTTPException(status_code=400, detail="Options and correct key are required for MCQ/MSQ/True-False questions")
    
    if question_data.type == QuestionType.NUMERIC:
        if question_data.correct_key is None:
            raise HTTPException(status_code=400, detail="Correct answer is required for numeric questions")
    
    # Set the subject_id
    question_data.subject_id = subject_id
    await db.questions.insert_one(question_data.dict())
    return question_data

@api_router.get("/questions/{question_id}", response_model=Question)
async def get_question(question_id: str, current_user: Dict = Depends(get_teacher_user)):
    """Get question by ID"""
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Verify user has access to this question's subject
    subject = await db.subjects.find_one({"id": question["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return Question(**question)

@api_router.put("/questions/{question_id}", response_model=Question)
async def update_question(question_id: str, question_data: Question, current_user: Dict = Depends(get_teacher_user)):
    """Update a question (teacher/admin only)"""
    # Verify question exists
    existing_question = await db.questions.find_one({"id": question_id})
    if not existing_question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Verify subject and user access
    subject = await db.subjects.find_one({"id": existing_question["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Verify CO exists and belongs to this subject
    co = await db.cos.find_one({"id": question_data.co_id, "subject_id": existing_question["subject_id"]})
    if not co:
        raise HTTPException(status_code=400, detail="CO not found in this subject")
    
    # Update question
    question_data.id = question_id
    question_data.subject_id = existing_question["subject_id"]
    question_data.updated_at = datetime.now(timezone.utc)
    question_data.version = existing_question.get("version", 1) + 1
    
    await db.questions.replace_one({"id": question_id}, question_data.dict())
    return question_data

@api_router.delete("/questions/{question_id}")
async def delete_question(question_id: str, current_user: Dict = Depends(get_teacher_user)):
    """Delete a question (teacher/admin only)"""
    # Verify question exists
    existing_question = await db.questions.find_one({"id": question_id})
    if not existing_question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Verify subject and user access
    subject = await db.subjects.find_one({"id": existing_question["subject_id"]})
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    
    if (current_user["role"] != UserRole.SUPER_ADMIN and 
        subject["teacher_id"] != current_user["id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if question is used in any exams
    exam_questions_count = await db.exam_questions.count_documents({"question_id": question_id})
    if exam_questions_count > 0:
        raise HTTPException(status_code=400, detail="Cannot delete question. It is being used in exams")
    
    await db.questions.delete_one({"id": question_id})
    return {"message": "Question deleted successfully"}

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
    await db.co_po_mappings.create_index([("co_id", 1), ("po_id", 1)], unique=True)
    await db.questions.create_index("subject_id")
    await db.questions.create_index("type")
    await db.questions.create_index("difficulty")
    await db.questions.create_index("co_id")
    await db.questions.create_index("tags")
    
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