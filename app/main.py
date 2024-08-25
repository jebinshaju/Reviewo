from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from jose import JWTError, jwt
from msal import ConfidentialClientApplication  # Microsoft login
from google.oauth2 import id_token  # Google login
from google.auth.transport import requests  # Google login
from pydantic import BaseModel
from dotenv import load_dotenv
import uuid
import os
import requests as external_requests
from app import models, database, utils

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
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Redirect URIs
REDIRECT_URI = "http://localhost:8000/auth/callback"
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"
SCOPES = ["User.Read"]

# Dependency for getting the database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic model for token data
class TokenData(BaseModel):
    email: str = None

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

@app.post("/email_login")
async def send_email_login_link(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    registration_token = str(uuid.uuid4())

    if not user:
        # Send registration email to new user
        utils.send_registration_email(email, registration_token)
        return JSONResponse(content={"message": "Registration email sent", "status": "new_user"})
    else:
        # For existing user, update the registration token but do not send email
        user.registration_token = registration_token
        db.commit()
        return JSONResponse(content={"message": "User exists, proceed to dashboard", "status": "existing_user", "token": registration_token})

@app.get("/register")
async def register_form(email: str, token: str, db: Session = Depends(get_db)):
    # Validate token and email
    user = db.query(models.User).filter(models.User.email == email, models.User.registration_token == token).first()
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
    user = db.query(models.User).filter(models.User.email == email, models.User.registration_token == token).first()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already registered")

    # Create a new user
    new_user = models.User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        user_name=user_name,
        phone=phone,
        time_zone=time_zone,
        scope=scope,
        about_us=about_us,
        is_active=True
    )

    # Assign new roles
    role_names = roles.split(',')
    for role_name in role_names:
        role = db.query(models.Role).filter(models.Role.role_name == role_name.strip()).first()
        if role:
            user_role = models.UserRole(user=new_user, role=role)
            db.add(user_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/login")
async def microsoft_login():
    auth_url = cca.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get("code")
    result = cca.acquire_token_by_authorization_code(code, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    if "error" in result:
        return JSONResponse(content=result, status_code=400)
    email = result["id_token_claims"].get("preferred_username")
    if not email:
        return JSONResponse(content={"error": "Email not found in token"}, status_code=400)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    registration_token = str(uuid.uuid4())
    utils.send_registration_email(email, registration_token)
    return JSONResponse(content={"message": "Registration email sent", "status": "new_user"})

@app.get("/google/login")
async def google_login():
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20email%20profile"
    )
    return RedirectResponse(url=google_auth_url)

@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get("code")
    try:
        token_request_uri = f"https://oauth2.googleapis.com/token"
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }
        token_response = external_requests.post(token_request_uri, data=token_data).json()
        idinfo = id_token.verify_oauth2_token(token_response["id_token"], requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo.get('email')
        if not email:
            return JSONResponse(content={"error": "Email not found in token"}, status_code=400)
        user = db.query(models.User).filter(models.User.email == email).first()
        if user:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
        registration_token = str(uuid.uuid4())
        utils.send_registration_email(email, registration_token)
        return JSONResponse(content={"message": "Registration email sent", "status": "new_user"})
    except ValueError:
        return JSONResponse(content={"error": "Invalid token"}, status_code=400)

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
    user = db.query(models.User).filter(models.User.email == email).first()
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
