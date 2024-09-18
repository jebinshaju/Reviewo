from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, relationship
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from jose import JWTError, jwt
from msal import ConfidentialClientApplication  # Microsoft login
from google.oauth2 import id_token  # Google login
from google.auth.transport import requests  # Google login
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import uuid
import os
import requests as external_requests

# Load environment variables
load_dotenv()

app = FastAPI()

# Environment variables for OAuth
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")
MICROSOFT_TENANT_ID = os.getenv("MICROSOFT_TENANT_ID")
MICROSOFT_AUTHORITY = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # Replace with your own secret key
ALGORITHM = "HS256"

# Redirect URIs
REDIRECT_URI = "http://localhost:8000/auth/callback"
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"
SCOPES = ["User.Read"]

# Database setup
DATABASE_URL = "sqlite:///./test.db"  # Replace with your database URL
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Models

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    users = relationship("User", back_populates="tenant")
    organizations = relationship("Organization", back_populates="tenant")
    apps = relationship("AppSubscription", back_populates="tenant")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    user_name = Column(String, unique=True, index=True, nullable=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, nullable=True)
    time_zone = Column(String, nullable=True)
    scope = Column(String, nullable=True)
    about_us = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    registration_token = Column(String, nullable=True)
    type = Column(String, default="ActionUser")  # Admin, Tenant, ActionUser
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    tenant = relationship("Tenant", back_populates="users")
    roles = relationship("UserRole", back_populates="user")
    organizations = relationship("Organization", back_populates="contact_person")

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String, unique=True)
    user_roles = relationship("UserRole", back_populates="role")

class UserRole(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    role_id = Column(Integer, ForeignKey("roles.id"))
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    legal_name = Column(String)
    address = Column(String)
    neighborhood = Column(String)
    city = Column(String)
    state = Column(String)
    country = Column(String)
    postal_code = Column(String)
    time_zone = Column(String)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    tenant = relationship("Tenant", back_populates="organizations")
    contact_person_id = Column(Integer, ForeignKey("users.id"))
    contact_person = relationship("User", back_populates="organizations")

class App(Base):
    __tablename__ = "apps"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    subscriptions = relationship("AppSubscription", back_populates="app")

class AppSubscription(Base):
    __tablename__ = "app_subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    app_id = Column(Integer, ForeignKey("apps.id"))
    tenant = relationship("Tenant", back_populates="apps")
    app = relationship("App", back_populates="subscriptions")

# Create all tables
Base.metadata.create_all(bind=engine)

# Dependency for getting the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions (e.g., sending emails)
def send_registration_email(email: str, token: str):
    # Implement your email sending logic here
    print(f"Sending registration email to {email} with token {token}")

# Pydantic models for request bodies
class TokenData(BaseModel):
    email: str = None

class AddUserRequest(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    mobile_number: int

class AddOrganisationRequest(BaseModel):
    legalname: str
    address: str
    neighbourhood: str
    city: str
    province: str
    country: str
    postalcode: int
    timezone: str

# Microsoft authentication app configuration
app_config = {
    "client_id": MICROSOFT_CLIENT_ID,
    "authority": MICROSOFT_AUTHORITY,
    "client_credential": MICROSOFT_CLIENT_SECRET,
}
cca = ConfidentialClientApplication(**app_config)

# OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/")
async def home():
    return {
        "msg": "Welcome to the site. Use /login to login or signup.",
        "endpoints": {
            "documentation": "/docs",
            "email_login": "/email_login",
            "google_login": "/google/login",
            "microsoft_login": "/login"
        }
    }

# Existing endpoints...

# New endpoint: Add Users
@app.post("/add-users")
async def add_users(request: AddUserRequest, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.email == request.email).first()
        if existing_user:
            return {"status": False, "message": "User already exists"}

        new_user = User(
            first_name=request.firstname,
            last_name=request.lastname,
            email=request.email,
            phone=str(request.mobile_number)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"status": True, "message": "User Added"}
    except Exception as e:
        print(f"Error adding user: {e}")
        return {"status": False, "message": "User not Added"}

# New endpoint: Add Organisation
@app.post("/add-organisation")
async def add_organisation(request: AddOrganisationRequest, db: Session = Depends(get_db)):
    try:
        valid_timezones = [
            "Pacific/Midway", "Pacific/Pago_Pago", "Pacific/Honolulu",
            "America/Anchorage", "America/Los_Angeles", "America/Denver",
            "America/Chicago", "America/New_York", "America/Caracas",
            "America/Halifax", "America/St_Johns", "America/Argentina/Buenos_Aires",
            "America/Noronha", "Atlantic/Azores", "Europe/London", "Europe/Berlin",
            "Africa/Johannesburg", "Asia/Baghdad", "Asia/Tehran", "Asia/Dubai",
            "Asia/Kabul", "Asia/Karachi", "Asia/Kolkata", "Asia/Kathmandu",
            "Asia/Dhaka", "Asia/Yangon", "Asia/Bangkok", "Asia/Shanghai",
            "Australia/Eucla", "Asia/Tokyo", "Australia/Adelaide",
            "Australia/Sydney", "Australia/Lord_Howe", "Asia/Magadan",
            "Pacific/Norfolk", "Pacific/Auckland", "Pacific/Chatham",
            "Pacific/Tongatapu", "Pacific/Kiritimati"
        ]
        if request.timezone not in valid_timezones:
            return {"status": False, "message": "Invalid timezone"}

        new_org = Organization(
            legal_name=request.legalname,
            address=request.address,
            neighborhood=request.neighbourhood,
            city=request.city,
            state=request.province,  # Mapping 'province' to 'state' in the model
            country=request.country,
            postal_code=str(request.postalcode),
            time_zone=request.timezone
        )
        db.add(new_org)
        db.commit()
        db.refresh(new_org)
        return {"status": True, "message": "Organisation added..!"}
    except Exception as e:
        print(f"Error adding organisation: {e}")
        return {"status": False, "message": "Organisation couldn't be added..!"}

# Rest of your existing endpoints...

# For demonstration purposes, here are some of the existing endpoints:

@app.post("/email_login")
async def send_email_login_link(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    registration_token = str(uuid.uuid4())

    if not user:
        # Send registration email to new user
        send_registration_email(email, registration_token)
        return JSONResponse(content={"message": "Registration email sent", "status": "new_user"})
    else:
        # For existing user, update the registration token but do not send email
        user.registration_token = registration_token
        db.commit()
        return JSONResponse(content={"message": "User exists, proceed to dashboard", "status": "existing_user", "token": registration_token})

@app.get("/register")
async def register_form(email: str, token: str, db: Session = Depends(get_db)):
    # Validate token and email
    user = db.query(User).filter(User.email == email, User.registration_token == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid registration link")

    return {
        "form": {
            "email": user.email,
            "token": user.registration_token,
            "first_name": "First Name",
            "last_name": "Last Name",
            "user_name": "User Name",
            "phone": "Phone",
            "time_zone": "Time Zone (Drop Down)",
            "roles": "Roles (All Roles by Default)",
            "scope": "Scope (All Scope by Default)",
            "about_us": "About Us (Description)"
        }
    }

@app.post("/register")
async def register_user(
    email: str = Form(...),
    token: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    user_name: str = Form(...),
    phone: str = Form(...),
    time_zone: str = Form(...),
    roles: str = Form(...),  # Expecting a comma-separated string of role names
    scope: str = Form(...),
    about_us: str = Form(...),
    db: Session = Depends(get_db)
):
    # Verify user by email and token
    user = db.query(User).filter(User.email == email, User.registration_token == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or email")

    # Update user details
    user.first_name = first_name
    user.last_name = last_name
    user.user_name = user_name
    user.phone = phone
    user.time_zone = time_zone
    user.scope = scope
    user.about_us = about_us
    user.is_active = True
    user.registration_token = None  # Clear the token after registration

    # Assign new roles
    role_names = roles.split(',')
    for role_name in role_names:
        role = db.query(Role).filter(Role.role_name == role_name.strip()).first()
        if role:
            user_role = UserRole(user=user, role=role)
            db.add(user_role)

    db.commit()
    db.refresh(user)

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/dashboard")
async def dashboard(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = get_current_user(db, token)
    if current_user.type == "Admin":
        return {"msg": "Admin Dashboard", "data": admin_dashboard_data()}
    elif current_user.type == "Tenant":
        return {"msg": "Tenant Dashboard", "data": tenant_dashboard_data(current_user)}
    elif current_user.type == "ActionUser":
        return {"msg": "Action User Dashboard", "data": action_user_dashboard_data(current_user)}
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden")

def admin_dashboard_data():
    return {"organizations": [], "users": [], "apps": []}

def tenant_dashboard_data(user):
    return {"organizations": user.organizations, "users": user.users, "apps": user.apps}

def action_user_dashboard_data(user):
    return {"reviews": [], "apps": user.apps}

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/dashboard")
async def dashboard(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    if current_user.type == "Admin":
        return {"msg": "Admin Dashboard", "data": admin_dashboard_data()}
    elif current_user.type == "Tenant":
        return {"msg": "Tenant Dashboard", "data": tenant_dashboard_data(current_user)}
    elif current_user.type == "ActionUser":
        return {"msg": "Action User Dashboard", "data": action_user_dashboard_data(current_user)}
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden")

def admin_dashboard_data():
    return {"organizations": [], "users": [], "apps": []}

def tenant_dashboard_data(user):
    return {"organizations": user.organizations, "users": user.users, "apps": user.apps}

def action_user_dashboard_data(user):
    return {"reviews": user.reviews, "apps": user.apps}

@app.post("/organizations")
async def create_organization(
    legal_name: str = Form(...),
    address: str = Form(...),
    neighborhood: str = Form(...),
    city: str = Form(...),
    state: str = Form(...),
    country: str = Form(...),
    postal_code: str = Form(...),
    time_zone: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    organization = models.Organization(
        legal_name=legal_name,
        address=address,
        neighborhood=neighborhood,
        city=city,
        state=state,
        country=country,
        postal_code=postal_code,
        time_zone=time_zone,
        tenant=current_user.tenant
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    return {"msg": "Organization created successfully", "organization": organization}

@app.get("/organizations")
async def get_organizations(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    organizations = db.query(models.Organization).filter(models.Organization.tenant_id == current_user.tenant_id).all()
    return {"organizations": organizations}

@app.post("/action_users")
async def create_action_user(
    first_name: str = Form(...),
    last_name: str = Form(...),
    phone: str = Form(...),
    time_zone: str = Form(...),
    organization_id: int = Form(...),
    job_title: str = Form(...),
    roles_permissions: str = Form(...),  # This should be a comma-separated string of roles
    all_scope: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    action_user = models.User(
        first_name=first_name,
        last_name=last_name,
        phone=phone,
        time_zone=time_zone,
        tenant=current_user.tenant,
        roles=roles_permissions.split(','),  # Assuming a method to manage these roles
        scope="All" if all_scope else "Limited"
    )
    db.add(action_user)
    db.commit()
    db.refresh(action_user)
    return {"msg": "Action user created successfully", "action_user": action_user}

@app.get("/apps")
async def get_apps(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    apps = db.query(models.App).all()
    return {"apps": apps}

@app.post("/apps/subscribe")
async def subscribe_app(
    app_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    subscription = models.AppSubscription(
        tenant_id=current_user.tenant_id,
        app_id=app_id
    )
    db.add(subscription)
    db.commit()
    return {"msg": "Subscribed to app successfully"}

@app.post("/apps/unsubscribe")
async def unsubscribe_app(
    app_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    subscription = db.query(models.AppSubscription).filter_by(
        tenant_id=current_user.tenant_id,
        app_id=app_id
    ).first()
    if subscription:
        db.delete(subscription)
        db.commit()
        return {"msg": "Unsubscribed from app successfully"}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")
