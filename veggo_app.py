"""
VegGo - Complete Vegetable Delivery Platform
Single-file FastAPI application with MongoDB, Google OAuth, Real-time Tracking
Deploy on Render: https://render.com
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from bson import ObjectId
import jwt
import os
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets

# ============================================================================
# CONFIGURATION
# ============================================================================

# Environment Variables
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
WAREHOUSE_LAT = float(os.getenv("WAREHOUSE_LAT", "40.7128"))
WAREHOUSE_LNG = float(os.getenv("WAREHOUSE_LNG", "-74.0060"))

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# FastAPI App
app = FastAPI(title="VegGo API", version="1.0.0")

# CORS Configuration - Allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database
client = None
db = None

@app.on_event("startup")
async def startup_db_client():
    global client, db
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client.veggo
    print("✅ Connected to MongoDB")
    
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.admins.create_index("username", unique=True)
    await db.products.create_index("name")
    
    # Create default admin if not exists
    admin_exists = await db.admins.find_one({"username": "admin"})
    if not admin_exists:
        hashed_password = pwd_context.hash("admin123")
        await db.admins.insert_one({
            "username": "admin",
            "password": hashed_password,
            "role": "superadmin",
            "createdAt": datetime.utcnow()
        })
        print("✅ Default admin created: username=admin, password=admin123")

@app.on_event("shutdown")
async def shutdown_db_client():
    global client
    if client:
        client.close()
        print("❌ Disconnected from MongoDB")

# ============================================================================
# MODELS
# ============================================================================

class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class GoogleLogin(BaseModel):
    token: str

class Product(BaseModel):
    name: str
    imageUrl: str
    unitType: str  # "kg", "piece", "both"
    pricePerKg: Optional[float] = 0
    pricePerPiece: Optional[float] = 0
    stockKg: Optional[float] = 0
    stockPieces: Optional[int] = 0
    category: str
    isAvailable: bool = True

class OrderItem(BaseModel):
    productId: str
    productName: str
    unit: str  # "kg" or "piece"
    quantity: float
    price: float

class OrderCreate(BaseModel):
    customerName: str
    phone: str
    address: str
    latitude: float
    longitude: float
    items: List[OrderItem]

class AdminLogin(BaseModel):
    username: str
    password: str

class AgentLogin(BaseModel):
    phone: str
    password: str

class LocationUpdate(BaseModel):
    latitude: float
    longitude: float

class OrderStatusUpdate(BaseModel):
    status: str

class AssignAgent(BaseModel):
    agentId: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    newPassword: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None

# ============================================================================
# UTILITIES
# ============================================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(user_id: str, role: str = "user") -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("user_id")
    role = payload.get("role")
    
    if role == "admin":
        user = await db.admins.find_one({"_id": ObjectId(user_id)})
    elif role == "agent":
        user = await db.agents.find_one({"_id": ObjectId(user_id)})
    else:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    user["_id"] = str(user["_id"])
    user["role"] = role
    return user

async def send_email(to_email: str, subject: str, body: str):
    """Send email using SMTP"""
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"📧 Email not configured. Would send to {to_email}: {subject}")
        return
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")

async def calculate_delivery_fee(customer_lat: float, customer_lng: float) -> float:
    """Calculate delivery fee based on distance using Google Maps Distance Matrix API"""
    if not GOOGLE_MAPS_API_KEY:
        return 5.0  # Default delivery fee
    
    try:
        url = "https://maps.googleapis.com/maps/api/distancematrix/json"
        params = {
            "origins": f"{WAREHOUSE_LAT},{WAREHOUSE_LNG}",
            "destinations": f"{customer_lat},{customer_lng}",
            "key": GOOGLE_MAPS_API_KEY
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params)
            data = response.json()
            
            if data["status"] == "OK":
                distance = data["rows"][0]["elements"][0]["distance"]["value"]  # meters
                distance_km = distance / 1000
                delivery_fee = 2.0 + (distance_km * 1.0)  # $2 base + $1/km
                return round(delivery_fee, 2)
    except Exception as e:
        print(f"⚠️ Error calculating delivery fee: {str(e)}")
    
    return 5.0

def serialize_doc(doc):
    """Convert MongoDB document to JSON-serializable format"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        doc = dict(doc)
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                doc[key] = str(value)
            elif isinstance(value, datetime):
                doc[key] = value.isoformat()
            elif isinstance(value, dict):
                doc[key] = serialize_doc(value)
            elif isinstance(value, list):
                doc[key] = serialize_doc(value)
        return doc
    return doc

# ============================================================================
# USER ROUTES
# ============================================================================

@app.post("/api/user/signup")
async def user_signup(user: UserSignup):
    """User registration with email verification"""
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)
    verification_token = secrets.token_urlsafe(32)
    
    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "verified": False,
        "verificationToken": verification_token,
        "createdAt": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_doc)
    
    # Send verification email
    verification_link = f"{BASE_URL}/api/user/verify-email?token={verification_token}"
    email_body = f"""
    <h2>Welcome to VegGo! 🥬</h2>
    <p>Thank you for signing up. Please verify your email by clicking the link below:</p>
    <a href="{verification_link}" style="display: inline-block; padding: 10px 20px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
    <p>If you didn't create this account, please ignore this email.</p>
    """
    await send_email(user.email, "Verify Your VegGo Account", email_body)
    
    token = create_token(str(result.inserted_id), "user")
    
    return {
        "message": "User registered successfully. Please check your email to verify your account.",
        "token": token,
        "userId": str(result.inserted_id)
    }

@app.get("/api/user/verify-email")
async def verify_email(token: str):
    """Verify user email"""
    user = await db.users.find_one({"verificationToken": token})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"verified": True}, "$unset": {"verificationToken": ""}}
    )
    
    return HTMLResponse("""
        <html>
            <body style="font-family: Arial; text-align: center; padding: 50px; background: #f5f5f5;">
                <div style="background: white; max-width: 500px; margin: 0 auto; padding: 40px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">
                    <h1 style="color: #4CAF50;">✓ Email Verified!</h1>
                    <p style="color: #666; font-size: 16px;">Your email has been successfully verified.</p>
                    <p style="color: #666;">You can now close this window and enjoy VegGo!</p>
                </div>
            </body>
        </html>
    """)

@app.post("/api/user/login")
async def user_login(credentials: UserLogin):
    """User login"""
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(str(user["_id"]), "user")
    
    return {
        "message": "Login successful",
        "token": token,
        "userId": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "verified": user.get("verified", False)
    }

@app.post("/api/user/google-login")
async def google_login(data: GoogleLogin):
    """Login/Signup with Google OAuth"""
    try:
        # Verify Google token
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={data.token}"
            )
            google_data = response.json()
        
        if "error" in google_data:
            raise HTTPException(status_code=400, detail="Invalid Google token")
        
        email = google_data.get("email")
        google_id = google_data.get("sub")
        name = google_data.get("name", email.split("@")[0])
        
        # Find or create user
        user = await db.users.find_one({"$or": [{"email": email}, {"googleId": google_id}]})
        
        if not user:
            user_doc = {
                "username": name,
                "email": email,
                "googleId": google_id,
                "verified": True,
                "createdAt": datetime.utcnow()
            }
            result = await db.users.insert_one(user_doc)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user["_id"])
            if not user.get("googleId"):
                await db.users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"googleId": google_id, "verified": True}}
                )
        
        token = create_token(user_id, "user")
        
        return {
            "message": "Google login successful",
            "token": token,
            "userId": user_id,
            "email": email,
            "username": name
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google login failed: {str(e)}")

@app.post("/api/user/reset-password")
async def reset_password(data: PasswordReset):
    """Request password reset"""
    user = await db.users.find_one({"email": data.email})
    if not user:
        return {"message": "If the email exists, a reset link has been sent"}
    
    reset_token = secrets.token_urlsafe(32)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "resetToken": reset_token,
            "resetTokenExpiry": datetime.utcnow() + timedelta(hours=1)
        }}
    )
    
    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"
    email_body = f"""
    <h2>Password Reset Request</h2>
    <p>Click the link below to reset your password:</p>
    <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    """
    await send_email(data.email, "Reset Your VegGo Password", email_body)
    
    return {"message": "If the email exists, a reset link has been sent"}

@app.post("/api/user/reset-password-confirm")
async def reset_password_confirm(data: PasswordResetConfirm):
    """Confirm password reset"""
    user = await db.users.find_one({
        "resetToken": data.token,
        "resetTokenExpiry": {"$gt": datetime.utcnow()}
    })
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    hashed_password = hash_password(data.newPassword)
    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password": hashed_password},
            "$unset": {"resetToken": "", "resetTokenExpiry": ""}
        }
    )
    
    return {"message": "Password reset successful"}

@app.get("/api/user/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Get user profile"""
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Access denied")
    
    user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
    user_data = serialize_doc(user)
    user_data.pop("password", None)
    user_data.pop("resetToken", None)
    user_data.pop("verificationToken", None)
    
    return user_data

@app.put("/api/user/profile")
async def update_profile(profile: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    """Update user profile"""
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_data = {}
    if profile.name:
        update_data["username"] = profile.name
    if profile.phone:
        update_data["phone"] = profile.phone
    
    if update_data:
        await db.users.update_one(
            {"_id": ObjectId(current_user["_id"])},
            {"$set": update_data}
        )
    
    return {"message": "Profile updated successfully"}

@app.get("/api/user/orders")
async def get_user_orders(current_user: dict = Depends(get_current_user)):
    """Get user's orders"""
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Access denied")
    
    orders = await db.orders.find({"userId": current_user["_id"]}).sort("createdAt", -1).to_list(100)
    return serialize_doc(orders)

@app.get("/api/user/order/{order_id}")
async def get_order_details(order_id: str, current_user: dict = Depends(get_current_user)):
    """Get order details with agent tracking"""
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Access denied")
    
    order = await db.orders.find_one({
        "_id": ObjectId(order_id),
        "userId": current_user["_id"]
    })
    
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    order_data = serialize_doc(order)
    
    # Get agent location if assigned
    if order.get("assignedAgentId"):
        agent = await db.agents.find_one({"_id": ObjectId(order["assignedAgentId"])})
        if agent and agent.get("currentLocation"):
            order_data["agentLocation"] = agent["currentLocation"]
            order_data["agentName"] = agent.get("name")
            order_data["agentPhone"] = agent.get("phone")
    
    return order_data

# ============================================================================
# PRODUCT ROUTES
# ============================================================================

@app.get("/api/products")
async def get_products():
    """Get all available products"""
    products = await db.products.find({"isAvailable": True}).to_list(1000)
    return serialize_doc(products)

@app.get("/api/product/{product_id}")
async def get_product(product_id: str):
    """Get single product"""
    product = await db.products.find_one({"_id": ObjectId(product_id)})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return serialize_doc(product)

@app.post("/api/admin/product/add")
async def add_product(product: Product, current_user: dict = Depends(get_current_user)):
    """Add new product (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    product_doc = product.dict()
    product_doc["createdAt"] = datetime.utcnow()
    
    result = await db.products.insert_one(product_doc)
    return {
        "message": "Product added successfully",
        "productId": str(result.inserted_id)
    }

@app.put("/api/admin/product/update/{product_id}")
async def update_product(product_id: str, product: Product, current_user: dict = Depends(get_current_user)):
    """Update product (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.products.update_one(
        {"_id": ObjectId(product_id)},
        {"$set": product.dict()}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return {"message": "Product updated successfully"}

@app.delete("/api/admin/product/delete/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    """Delete product (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.products.delete_one({"_id": ObjectId(product_id)})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return {"message": "Product deleted successfully"}

# ============================================================================
# ORDER ROUTES
# ============================================================================

@app.post("/api/order/create")
async def create_order(order: OrderCreate, current_user: dict = Depends(get_current_user)):
    """Create new order"""
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="User access required")
    
    # Calculate total price
    total_price = sum(item.price * item.quantity for item in order.items)
    
    # Calculate delivery fee
    delivery_fee = await calculate_delivery_fee(order.latitude, order.longitude)
    
    # Create order document
    order_doc = {
        "userId": current_user["_id"],
        "customerName": order.customerName,
        "phone": order.phone,
        "address": order.address,
        "latitude": order.latitude,
        "longitude": order.longitude,
        "items": [item.dict() for item in order.items],
        "totalPrice": total_price,
        "deliveryFee": delivery_fee,
        "grandTotal": total_price + delivery_fee,
        "status": "Pending",
        "createdAt": datetime.utcnow()
    }
    
    result = await db.orders.insert_one(order_doc)
    
    # Send confirmation email
    user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
    email_body = f"""
    <h2>Order Confirmation 🥬</h2>
    <p>Thank you for your order!</p>
    <p><strong>Order ID:</strong> {str(result.inserted_id)}</p>
    <p><strong>Total:</strong> ${total_price:.2f}</p>
    <p><strong>Delivery Fee:</strong> ${delivery_fee:.2f}</p>
    <p><strong>Grand Total:</strong> ${total_price + delivery_fee:.2f}</p>
    <p>We'll notify you when your order is confirmed and out for delivery.</p>
    """
    await send_email(user["email"], "VegGo Order Confirmation", email_body)
    
    return {
        "message": "Order placed successfully",
        "orderId": str(result.inserted_id),
        "totalPrice": total_price,
        "deliveryFee": delivery_fee,
        "grandTotal": total_price + delivery_fee
    }

@app.get("/api/admin/orders")
async def get_all_orders(current_user: dict = Depends(get_current_user)):
    """Get all orders (Admin only) - Real-time updates"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    orders = await db.orders.find().sort("createdAt", -1).to_list(1000)
    return serialize_doc(orders)

@app.put("/api/admin/order/status/{order_id}")
async def update_order_status(order_id: str, status_update: OrderStatusUpdate, current_user: dict = Depends(get_current_user)):
    """Update order status (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    valid_statuses = ["Pending", "Confirmed", "Out for Delivery", "Delivered", "Cancelled"]
    if status_update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.orders.update_one(
        {"_id": ObjectId(order_id)},
        {"$set": {"status": status_update.status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    
    return {"message": "Order status updated successfully"}

@app.put("/api/admin/order/assign-agent/{order_id}")
async def assign_agent(order_id: str, agent_data: AssignAgent, current_user: dict = Depends(get_current_user)):
    """Assign delivery agent to order (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Verify agent exists
    agent = await db.agents.find_one({"_id": ObjectId(agent_data.agentId)})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    result = await db.orders.update_one(
        {"_id": ObjectId(order_id)},
        {"$set": {"assignedAgentId": agent_data.agentId, "status": "Out for Delivery"}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Add order to agent's assigned orders
    await db.agents.update_one(
        {"_id": ObjectId(agent_data.agentId)},
        {"$push": {"assignedOrders": order_id}}
    )
    
    return {"message": "Agent assigned successfully"}

# ============================================================================
# AGENT ROUTES
# ============================================================================

@app.post("/api/agent/login")
async def agent_login(credentials: AgentLogin):
    """Agent login"""
    agent = await db.agents.find_one({"phone": credentials.phone})
    if not agent or not verify_password(credentials.password, agent["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(str(agent["_id"]), "agent")
    
    return {
        "message": "Login successful",
        "token": token,
        "agentId": str(agent["_id"]),
        "name": agent["name"]
    }

@app.get("/api/agent/orders")
async def get_agent_orders(current_user: dict = Depends(get_current_user)):
    """Get agent's assigned orders"""
    if current_user["role"] != "agent":
        raise HTTPException(status_code=403, detail="Agent access required")
    
    orders = await db.orders.find({
        "assignedAgentId": current_user["_id"],
        "status": {"$in": ["Out for Delivery", "Confirmed"]}
    }).to_list(100)
    
    return serialize_doc(orders)

@app.put("/api/agent/update-location")
async def update_location(location: LocationUpdate, current_user: dict = Depends(get_current_user)):
    """Update agent's current location - Real-time tracking"""
    if current_user["role"] != "agent":
        raise HTTPException(status_code=403, detail="Agent access required")
    
    await db.agents.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": {
            "currentLocation": {
                "latitude": location.latitude,
                "longitude": location.longitude
            },
            "lastUpdated": datetime.utcnow()
        }}
    )
    
    return {"message": "Location updated successfully"}

@app.get("/api/agent/available")
async def get_available_agents(current_user: dict = Depends(get_current_user)):
    """Get all available agents (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    agents = await db.agents.find({"status": "available"}).to_list(100)
    return serialize_doc(agents)

@app.post("/api/admin/agent/create")
async def create_agent(name: str = Form(...), phone: str = Form(...), password: str = Form(...), current_user: dict = Depends(get_current_user)):
    """Create new delivery agent (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if agent exists
    existing = await db.agents.find_one({"phone": phone})
    if existing:
        raise HTTPException(status_code=400, detail="Agent with this phone already exists")
    
    hashed_password = hash_password(password)
    agent_doc = {
        "name": name,
        "phone": phone,
        "password": hashed_password,
        "status": "available",
        "assignedOrders": [],
        "createdAt": datetime.utcnow()
    }
    
    result = await db.agents.insert_one(agent_doc)
    
    return {
        "message": "Agent created successfully",
        "agentId": str(result.inserted_id)
    }

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.post("/api/admin/login")
async def admin_login(credentials: AdminLogin):
    """Admin login"""
    admin = await db.admins.find_one({"username": credentials.username})
    if not admin or not verify_password(credentials.password, admin["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(str(admin["_id"]), "admin")
    
    return {
        "message": "Login successful",
        "token": token,
        "adminId": str(admin["_id"]),
        "username": admin["username"]
    }

@app.get("/api/admin/dashboard-stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard statistics (Admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_products = await db.products.count_documents({})
    total_orders = await db.orders.count_documents({})
    pending_orders = await db.orders.count_documents({"status": "Pending"})
    total_users = await db.users.count_documents({})
    total_agents = await db.agents.count_documents({})
    
    # Recent orders
    recent_orders = await db.orders.find().sort("createdAt", -1).limit(10).to_list(10)
    
    return {
        "totalProducts": total_products,
        "totalOrders": total_orders,
        "pendingOrders": pending_orders,
        "totalUsers": total_users,
        "totalAgents": total_agents,
        "recentOrders": serialize_doc(recent_orders)
    }

# ============================================================================
# HTML INTERFACES
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Admin panel HTML interface"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VegGo Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .dashboard-container { max-width: 1400px; margin: 0 auto; display: none; }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: 600; }
        input, select, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 { color: #667eea; font-size: 32px; margin-bottom: 10px; }
        .stat-card p { color: #666; font-size: 14px; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab {
            padding: 12px 24px;
            background: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
            width: auto;
        }
        .tab.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .content-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            display: none;
        }
        .content-section.active { display: block; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        .status {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-confirmed { background: #d1ecf1; color: #0c5460; }
        .status-out-for-delivery { background: #cce5ff; color: #004085; }
        .status-delivered { background: #d4edda; color: #155724; }
        .status-cancelled { background: #f8d7da; color: #721c24; }
        .btn-small {
            padding: 6px 12px;
            font-size: 12px;
            width: auto;
            margin: 2px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .logout-btn { width: auto; padding: 10px 20px; background: #dc3545; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }
        .close {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
        }
        .error { color: #dc3545; margin-top: 10px; font-size: 14px; }
        .success { color: #28a745; margin-top: 10px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container" id="loginScreen">
        <h1>🥬 VegGo Admin</h1>
        <form id="loginForm">
            <div class="input-group">
                <label>Username</label>
                <input type="text" id="username" required value="admin">
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" id="password" required value="admin123">
            </div>
            <button type="submit">Login</button>
            <div id="loginError" class="error"></div>
        </form>
        <p style="margin-top: 20px; text-align: center; color: #666; font-size: 12px;">
            Default credentials: admin / admin123
        </p>
    </div>

    <div class="dashboard-container" id="dashboard">
        <div class="header">
            <h1>🥬 VegGo Admin Dashboard</h1>
            <button class="logout-btn" onclick="logout()">Logout</button>
        </div>

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <h3 id="totalProducts">0</h3>
                <p>Total Products</p>
            </div>
            <div class="stat-card">
                <h3 id="totalOrders">0</h3>
                <p>Total Orders</p>
            </div>
            <div class="stat-card">
                <h3 id="pendingOrders">0</h3>
                <p>Pending Orders</p>
            </div>
            <div class="stat-card">
                <h3 id="totalUsers">0</h3>
                <p>Total Users</p>
            </div>
            <div class="stat-card">
                <h3 id="totalAgents">0</h3>
                <p>Delivery Agents</p>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('orders')">Orders</button>
            <button class="tab" onclick="showTab('products')">Products</button>
            <button class="tab" onclick="showTab('agents')">Agents</button>
        </div>

        <div class="content-section active" id="ordersSection">
            <h2>Orders Management</h2>
            <table id="ordersTable">
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Customer</th>
                        <th>Phone</th>
                        <th>Total</th>
                        <th>Status</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <div class="content-section" id="productsSection">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Products Management</h2>
                <button onclick="showAddProductModal()" style="width: auto;">+ Add Product</button>
            </div>
            <table id="productsTable">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Unit Type</th>
                        <th>Price/Kg</th>
                        <th>Price/Piece</th>
                        <th>Stock</th>
                        <th>Category</th>
                        <th>Available</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <div class="content-section" id="agentsSection">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Delivery Agents</h2>
                <button onclick="showAddAgentModal()" style="width: auto;">+ Add Agent</button>
            </div>
            <table id="agentsTable">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Phone</th>
                        <th>Status</th>
                        <th>Assigned Orders</th>
                        <th>Last Updated</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <div class="modal" id="productModal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('productModal')">&times;</span>
            <h2 id="productModalTitle">Add Product</h2>
            <form id="productForm">
                <div class="input-group">
                    <label>Product Name</label>
                    <input type="text" id="productName" required>
                </div>
                <div class="input-group">
                    <label>Image URL</label>
                    <input type="url" id="productImage" required>
                </div>
                <div class="input-group">
                    <label>Unit Type</label>
                    <select id="productUnit" required>
                        <option value="kg">Kilogram (Kg)</option>
                        <option value="piece">Piece</option>
                        <option value="both">Both</option>
                    </select>
                </div>
                <div class="input-group">
                    <label>Price per Kg</label>
                    <input type="number" step="0.01" id="productPriceKg">
                </div>
                <div class="input-group">
                    <label>Price per Piece</label>
                    <input type="number" step="0.01" id="productPricePiece">
                </div>
                <div class="input-group">
                    <label>Stock (Kg)</label>
                    <input type="number" step="0.1" id="productStockKg">
                </div>
                <div class="input-group">
                    <label>Stock (Pieces)</label>
                    <input type="number" id="productStockPieces">
                </div>
                <div class="input-group">
                    <label>Category</label>
                    <input type="text" id="productCategory" required>
                </div>
                <div class="input-group">
                    <label>
                        <input type="checkbox" id="productAvailable" checked style="width: auto;">
                        Available for Sale
                    </label>
                </div>
                <button type="submit">Save Product</button>
                <div id="productError" class="error"></div>
            </form>
        </div>
    </div>

    <div class="modal" id="agentModal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('agentModal')">&times;</span>
            <h2>Add Delivery Agent</h2>
            <form id="agentForm">
                <div class="input-group">
                    <label>Agent Name</label>
                    <input type="text" id="agentName" required>
                </div>
                <div class="input-group">
                    <label>Phone Number</label>
                    <input type="tel" id="agentPhone" required>
                </div>
                <div class="input-group">
                    <label>Password</label>
                    <input type="password" id="agentPassword" required>
                </div>
                <button type="submit">Add Agent</button>
                <div id="agentError" class="error"></div>
            </form>
        </div>
    </div>

    <script>
        let token = localStorage.getItem('adminToken');
        const API_URL = window.location.origin;

        if (token) { showDashboard(); }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch(`${API_URL}/api/admin/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    token = data.token;
                    localStorage.setItem('adminToken', token);
                    showDashboard();
                } else {
                    document.getElementById('loginError').textContent = data.detail || 'Login failed';
                }
            } catch (error) {
                document.getElementById('loginError').textContent = 'Connection error';
            }
        });

        async function showDashboard() {
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            await loadDashboardData();
            setInterval(loadDashboardData, 5000); // Refresh every 5 seconds for real-time
        }

        function logout() {
            localStorage.removeItem('adminToken');
            location.reload();
        }

        async function loadDashboardData() {
            try {
                const response = await fetch(`${API_URL}/api/admin/dashboard-stats`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('totalProducts').textContent = data.totalProducts;
                    document.getElementById('totalOrders').textContent = data.totalOrders;
                    document.getElementById('pendingOrders').textContent = data.pendingOrders;
                    document.getElementById('totalUsers').textContent = data.totalUsers;
                    document.getElementById('totalAgents').textContent = data.totalAgents;
                }
                
                await loadOrders();
                await loadProducts();
                await loadAgents();
            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }

        async function loadOrders() {
            try {
                const response = await fetch(`${API_URL}/api/admin/orders`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                
                if (response.ok) {
                    const orders = await response.json();
                    const tbody = document.querySelector('#ordersTable tbody');
                    tbody.innerHTML = orders.map(order => `
                        <tr>
                            <td>${order._id.substring(0, 8)}...</td>
                            <td>${order.customerName}</td>
                            <td>${order.phone}</td>
                            <td>$${order.grandTotal.toFixed(2)}</td>
                            <td><span class="status status-${order.status.toLowerCase().replace(/ /g, '-')}">${order.status}</span></td>
                            <td>${new Date(order.createdAt).toLocaleDateString()}</td>
                            <td>
                                <button class="btn-small" onclick="updateOrderStatus('${order._id}')">Update Status</button>
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading orders:', error);
            }
        }

        async function loadProducts() {
            try {
                const response = await fetch(`${API_URL}/api/products`);
                
                if (response.ok) {
                    const products = await response.json();
                    const tbody = document.querySelector('#productsTable tbody');
                    tbody.innerHTML = products.map(product => `
                        <tr>
                            <td>${product.name}</td>
                            <td>${product.unitType}</td>
                            <td>${product.pricePerKg ? '$' + product.pricePerKg.toFixed(2) : '-'}</td>
                            <td>${product.pricePerPiece ? '$' + product.pricePerPiece.toFixed(2) : '-'}</td>
                            <td>${product.stockKg || 0} kg / ${product.stockPieces || 0} pcs</td>
                            <td>${product.category}</td>
                            <td>${product.isAvailable ? '✓' : '✗'}</td>
                            <td>
                                <button class="btn-small" onclick="deleteProduct('${product._id}')">Delete</button>
                            </td>
                        </tr>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading products:', error);
            }
        }

        async function loadAgents() {
            try {
                const response = await fetch(`${API_URL}/api/agent/available`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                
                if (response.ok) {
                    const agents = await response.json();
                    const tbody = document.querySelector('#agentsTable tbody');
                    tbody.innerHTML = agents.map(agent => `
                        <tr>
                            <td>${agent.name}</td>
                            <td>${agent.phone}</td>
                            <td>${agent.status}</td>
                            <td>${agent.assignedOrders ? agent.assignedOrders.length : 0}</td>
                            <td>${agent.lastUpdated ? new Date(agent.lastUpdated).toLocaleString() : 'Never'}</td>
                        </tr>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading agents:', error);
            }
        }

        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName + 'Section').classList.add('active');
        }

        function showAddProductModal() {
            document.getElementById('productModalTitle').textContent = 'Add Product';
            document.getElementById('productForm').reset();
            document.getElementById('productModal').style.display = 'flex';
        }

        document.getElementById('productForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const productData = {
                name: document.getElementById('productName').value,
                imageUrl: document.getElementById('productImage').value,
                unitType: document.getElementById('productUnit').value,
                pricePerKg: parseFloat(document.getElementById('productPriceKg').value) || 0,
                pricePerPiece: parseFloat(document.getElementById('productPricePiece').value) || 0,
                stockKg: parseFloat(document.getElementById('productStockKg').value) || 0,
                stockPieces: parseInt(document.getElementById('productStockPieces').value) || 0,
                category: document.getElementById('productCategory').value,
                isAvailable: document.getElementById('productAvailable').checked
            };
            
            try {
                const response = await fetch(`${API_URL}/api/admin/product/add`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify(productData)
                });
                
                if (response.ok) {
                    closeModal('productModal');
                    await loadProducts();
                    await loadDashboardData();
                } else {
                    const error = await response.json();
                    document.getElementById('productError').textContent = error.detail || 'Failed to add product';
                }
            } catch (error) {
                document.getElementById('productError').textContent = 'Connection error';
            }
        });

        function showAddAgentModal() {
            document.getElementById('agentForm').reset();
            document.getElementById('agentModal').style.display = 'flex';
        }

        document.getElementById('agentForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData();
            formData.append('name', document.getElementById('agentName').value);
            formData.append('phone', document.getElementById('agentPhone').value);
            formData.append('password', document.getElementById('agentPassword').value);
            
            try {
                const response = await fetch(`${API_URL}/api/admin/agent/create`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` },
                    body: formData
                });
                
                if (response.ok) {
                    closeModal('agentModal');
                    await loadAgents();
                    await loadDashboardData();
                } else {
                    const error = await response.json();
                    document.getElementById('agentError').textContent = error.detail || 'Failed to add agent';
                }
            } catch (error) {
                document.getElementById('agentError').textContent = 'Connection error';
            }
        });

        async function deleteProduct(productId) {
            if (!confirm('Are you sure you want to delete this product?')) return;
            
            try {
                const response = await fetch(`${API_URL}/api/admin/product/delete/${productId}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                
                if (response.ok) {
                    await loadProducts();
                    await loadDashboardData();
                }
            } catch (error) {
                console.error('Error deleting product:', error);
            }
        }

        async function updateOrderStatus(orderId) {
            const newStatus = prompt('Enter new status:\\n- Pending\\n- Confirmed\\n- Out for Delivery\\n- Delivered\\n- Cancelled');
            if (!newStatus) return;
            
            try {
                const response = await fetch(`${API_URL}/api/admin/order/status/${orderId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ status: newStatus })
                });
                
                if (response.ok) {
                    await loadOrders();
                    await loadDashboardData();
                } else {
                    alert('Invalid status');
                }
            } catch (error) {
                console.error('Error updating order:', error);
            }
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

@app.get("/", response_class=HTMLResponse)
async def home():
    """Landing page"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VegGo - Fresh Vegetables Delivered</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 60px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 600px;
        }
        h1 {
            font-size: 48px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
        p {
            font-size: 18px;
            color: #666;
            margin-bottom: 40px;
            line-height: 1.6;
        }
        .buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        a {
            display: inline-block;
            padding: 15px 40px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        a:hover {
            background: #45a049;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .admin-link {
            background: #667eea;
        }
        .admin-link:hover {
            background: #5568d3;
        }
        .features {
            margin-top: 40px;
            text-align: left;
        }
        .feature {
            margin: 15px 0;
            color: #555;
        }
        .feature::before {
            content: "✓ ";
            color: #4CAF50;
            font-weight: bold;
            margin-right: 10px;
        }
        .api-docs {
            margin-top: 30px;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 10px;
        }
        code {
            background: #e0e0e0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🥬 VegGo</h1>
        <p>Fresh vegetables delivered to your door with real-time tracking and seamless ordering experience.</p>
        
        <div class="buttons">
            <a href="/admin">Admin Panel</a>
            <a href="/docs" class="admin-link">API Documentation</a>
        </div>
        
        <div class="features">
            <h3 style="color: #333; margin-bottom: 15px;">Features:</h3>
            <div class="feature">User Registration & Google OAuth</div>
            <div class="feature">Email Verification & Password Reset</div>
            <div class="feature">Product Management (Kg/Piece/Both)</div>
            <div class="feature">Real-time Order Tracking</div>
            <div class="feature">Google Maps Distance-based Delivery Fee</div>
            <div class="feature">Delivery Agent Management</div>
            <div class="feature">Live Location Tracking</div>
            <div class="feature">Admin Dashboard with Statistics</div>
            <div class="feature">Email Notifications</div>
            <div class="feature">CORS Enabled for Mobile Apps</div>
        </div>
        
        <div class="api-docs">
            <h4 style="color: #333; margin-bottom: 10px;">Quick Start:</h4>
            <p style="font-size: 14px; margin-bottom: 10px;">
                Default Admin: <code>admin</code> / <code>admin123</code>
            </p>
            <p style="font-size: 14px; margin-bottom: 0;">
                API Base URL: <code>${window.location.origin}/api</code>
            </p>
        </div>
    </div>
</body>
</html>
    """)

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for Render"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "VegGo API"
    }

# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
