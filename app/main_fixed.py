from fastapi import FastAPI, Depends, HTTPException, Query, status
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import hashlib

SECRET_KEY = "test-secret-key-for-development"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2880

DATABASE_URL = "sqlite:///./advertisements_fixed.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), nullable=False)
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
    email: str = Field(..., max_length=100)
    full_name: Optional[str] = Field(None, max_length=100)
    password: str = Field(..., min_length=6, max_length=50)


class UserPublic(BaseModel):
    id: int
    username: str
    email: str
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


def get_password_hash(password: str) -> str:
    """Хеширование пароля с помощью SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    return get_password_hash(plain_password) == hashed_password


security = HTTPBearer()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
        role: str = payload.get("role")

        if username is None or user_id is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


app = FastAPI(
    title="Advertisement Service API",
    description="Сервис объявлений с аутентификацией и ролями",
    version="2.0.0"
)



@app.get("/")
def root():
    return {
        "message": "Advertisement Service API v2.0",
        "docs": "/docs",
        "endpoints": {
            "public": [
                "POST /user - Создать пользователя",
                "GET /user/{id} - Получить пользователя",
                "GET /advertisement/{id} - Получить объявление",
                "GET /advertisement - Поиск объявлений",
                "POST /login - Аутентификация"
            ]
        }
    }


@app.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    """Аутентификация пользователя"""
    user = authenticate_user(db, login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )

    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user", response_model=UserPublic)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Создание нового пользователя"""
    try:
        db_user = db.query(User).filter(User.username == user.username).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Пользователь с таким именем уже существует")

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
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при создании пользователя: {str(e)}")


@app.get("/user/{user_id}", response_model=UserPublic)
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Получение пользователя по ID"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return user


@app.patch("/user/{user_id}", response_model=UserPublic)
def update_user(
        user_id: int,
        user_update: dict,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Обновление пользователя"""
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    allowed_fields = ["email", "full_name"]
    for field in allowed_fields:
        if field in user_update:
            setattr(user, field, user_update[field])


    if "password" in user_update:
        user.hashed_password = get_password_hash(user_update["password"])

    db.commit()
    db.refresh(user)
    return user


@app.delete("/user/{user_id}")
def delete_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Удаление пользователя"""

    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")


    db.query(Advertisement).filter(Advertisement.owner_id == user_id).delete()


    db.delete(user)
    db.commit()

    return {"message": "Пользователь удален"}



@app.get("/advertisement/{advertisement_id}", response_model=AdvertisementPublic)
def get_advertisement(advertisement_id: int, db: Session = Depends(get_db)):
    """Получение объявления по ID"""
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    return ad


@app.get("/advertisement", response_model=List[AdvertisementPublic])
def search_advertisements(
        title: Optional[str] = Query(None, description="Поиск по заголовку"),
        description: Optional[str] = Query(None, description="Поиск по описанию"),
        price_min: Optional[float] = Query(None, description="Минимальная цена", ge=0),
        price_max: Optional[float] = Query(None, description="Максимальная цена", ge=0),
        author: Optional[str] = Query(None, description="Поиск по автору"),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        db: Session = Depends(get_db)
):
    """Поиск объявлений"""
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



@app.post("/advertisement", response_model=AdvertisementPublic)
def create_advertisement(
        advertisement: AdvertisementCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Создание нового объявления"""

    if current_user.role not in ["user", "admin"]:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    db_ad = Advertisement(
        **advertisement.dict(),
        owner_id=current_user.id
    )
    db.add(db_ad)
    db.commit()
    db.refresh(db_ad)
    return db_ad


@app.delete("/advertisement/{advertisement_id}")
def delete_advertisement(
        advertisement_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Удаление объявления"""
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Объявление не найдено")


    if current_user.role != "admin" and current_user.id != ad.owner_id:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    db.delete(ad)
    db.commit()

    return {"message": "Объявление удалено"}


@app.patch("/advertisement/{advertisement_id}", response_model=AdvertisementPublic)
def update_advertisement(
        advertisement_id: int,
        advertisement_update: dict,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Обновление объявления"""
    ad = db.query(Advertisement).filter(Advertisement.id == advertisement_id).first()
    if not ad:
        raise HTTPException(status_code=404, detail="Объявление не найдено")


    if current_user.role != "admin" and current_user.id != ad.owner_id:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    allowed_fields = ["title", "description", "price", "author"]
    for field in allowed_fields:
        if field in advertisement_update:
            setattr(ad, field, advertisement_update[field])

    db.commit()
    db.refresh(ad)
    return ad


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)