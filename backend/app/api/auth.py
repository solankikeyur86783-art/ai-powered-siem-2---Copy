"""
Authentication API — Register, Login, Profile
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from app.database.db import col
from app.core.auth_middleware import (
    hash_password, verify_password, create_access_token, get_current_user
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = ""


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
async def register(req: RegisterRequest):
    existing = await col("users").find_one({"username": req.username})
    if existing:
        raise HTTPException(400, "Username already exists")

    email_exists = await col("users").find_one({"email": req.email})
    if email_exists:
        raise HTTPException(400, "Email already registered")

    user = {
        "username": req.username,
        "email": req.email,
        "password_hash": hash_password(req.password),
        "role": "analyst",
        "full_name": req.full_name or req.username,
        "created_at": datetime.utcnow(),
        "is_active": True,
    }
    result = await col("users").insert_one(user)
    token = create_access_token({"sub": req.username, "role": "analyst"})

    return {
        "success": True,
        "token": token,
        "user": {
            "id": str(result.inserted_id),
            "username": req.username,
            "email": req.email,
            "role": "analyst",
            "full_name": user["full_name"],
        }
    }


@router.post("/login")
async def login(req: LoginRequest):
    user = await col("users").find_one({"username": req.username})
    if not user:
        raise HTTPException(401, "Invalid credentials")

    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(403, "Account disabled")

    token = create_access_token({
        "sub": user["username"],
        "role": user.get("role", "analyst")
    })

    # Update last login
    await col("users").update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.utcnow()}}
    )

    return {
        "success": True,
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user.get("email", ""),
            "role": user.get("role", "analyst"),
            "full_name": user.get("full_name", user["username"]),
        }
    }


@router.get("/me")
async def get_profile(user: dict = Depends(get_current_user)):
    return {"user": user}


@router.put("/me")
async def update_profile(updates: dict, user: dict = Depends(get_current_user)):
    allowed = {"full_name", "email"}
    filtered = {k: v for k, v in updates.items() if k in allowed and v}
    if filtered:
        from bson import ObjectId
        await col("users").update_one(
            {"_id": ObjectId(user["id"])},
            {"$set": filtered}
        )
    return {"success": True}
