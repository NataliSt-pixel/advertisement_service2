from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid

app = FastAPI()

users_db = {}
ads_db = {}
tokens_db = {}



class UserCreate(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class AdvertisementCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    author: str



def get_password_hash(password: str) -> str:
    return password + "_hashed"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password



@app.post("/login")
def login(login_data: LoginRequest):
    user = users_db.get(login_data.username)
    if not user or not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = str(uuid.uuid4())
    tokens_db[token] = login_data.username
    return {"access_token": token, "token_type": "bearer"}


@app.post("/user")
def create_user(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.username] = {
        "id": len(users_db) + 1,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "role": "user",
        "created_at": datetime.now()
    }

    return users_db[user.username]


@app.get("/user/{user_id}")
def get_user(user_id: int):
    for user in users_db.values():
        if user["id"] == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/advertisement")
def create_advertisement(ad: AdvertisementCreate, token: Optional[str] = None):
    if not token or token not in tokens_db:
        raise HTTPException(status_code=401, detail="Authentication required")

    username = tokens_db[token]
    user = users_db.get(username)

    if not user or user["role"] not in ["user", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    ad_id = len(ads_db) + 1
    ads_db[ad_id] = {
        "id": ad_id,
        "title": ad.title,
        "description": ad.description,
        "price": ad.price,
        "author": ad.author,
        "owner_id": user["id"],
        "created_at": datetime.now()
    }

    return ads_db[ad_id]


@app.get("/advertisement/{ad_id}")
def get_advertisement(ad_id: int):
    ad = ads_db.get(ad_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")
    return ad


@app.get("/advertisement")
def search_advertisements(
        title: Optional[str] = None,
        price_min: Optional[float] = None,
        price_max: Optional[float] = None
):
    results = []
    for ad in ads_db.values():
        if title and title.lower() not in ad["title"].lower():
            continue
        if price_min is not None and ad["price"] < price_min:
            continue
        if price_max is not None and ad["price"] > price_max:
            continue
        results.append(ad)
    return results


@app.get("/")
def root():
    return {
        "message": "Simple Advertisement API",
        "users_count": len(users_db),
        "ads_count": len(ads_db),
        "endpoints": [
            "POST /user - Create user",
            "POST /login - Login",
            "POST /advertisement - Create ad (requires auth)",
            "GET /advertisement - Search ads",
            "GET /advertisement/{id} - Get ad by id"
        ]
    }