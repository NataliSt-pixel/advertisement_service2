from fastapi import FastAPI, Depends, HTTPException, Query, status
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os


SECRET_KEY = "test-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2880


SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    advertisements = relationship("Advertisement", back_populates="owner")


class Advertisement(Base):
    __tablename__ = "advertisements"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    price = Column(Float, nullable=False)
    author = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="advertisements")



Base.metadata.create_all(bind=engine)



class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    password: str = Field(..., min_length=6)


class UserPublic(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class AdvertisementCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    price: float = Field(..., gt=0)
    author: str = Field(..., min_length=1, max_length=100)


class AdvertisementPublic(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    price: float
    author: str
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if username is None or user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user



app = FastAPI(title="Advertisement Service API", version="1.0.0")



@app.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, login_data.username, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user", response_model=UserPublic)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    db_user_email = db.query(User).filter(User.email == user.email).first()
    if db_user_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        role="user"
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/user/{user_id}", response_model=UserPublic)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/advertisement", response_model=AdvertisementPublic)
def create_advertisement(
        advertisement: AdvertisementCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role not in ["user", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    db_ad = Advertisement(
        **advertisement.dict(),
        owner_id=current_user.id
    )
    db.add(db_ad)
    db.commit()
    db.refresh(db_ad)
    return db_ad


@app.get("/advertisement/{advertisement_id}", response_model=AdvertisementPublic)
def get_advertisement(advertisement_id: int, db: Session = Depends(get_db)):
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")
    return ad


@app.get("/advertisement", response_model=List[AdvertisementPublic])
def search_advertisements(
        title: Optional[str] = None,
        description: Optional[str] = None,
        price_min: Optional[float] = None,
        price_max: Optional[float] = None,
        author: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db)
):
    query = db.query(Advertisement)

    if title:
        query = query.filter(Advertisement.title.contains(title))
    if description:
        query = query.filter(Advertisement.description.contains(description))
    if price_min is not None:
        query = query.filter(Advertisement.price >= price_min)
    if price_max is not None:
        query = query.filter(Advertisement.price <= price_max)
    if author:
        query = query.filter(Advertisement.author.contains(author))

    return query.offset(skip).limit(limit).all()


@app.get("/")
def root():
    return {
        "message": "Advertisement Service API",
        "docs": "/docs",
        "endpoints": {
            "public": [
                "POST /user - Create user",
                "GET /user/{id} - Get user",
                "GET /advertisement/{id} - Get advertisement",
                "GET /advertisement - Search advertisements",
                "POST /login - Login"
            ],
            "protected": [
                "POST /advertisement - Create advertisement (requires auth)"
            ]
        }
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)