from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid

app = FastAPI(
    title="Advertisement Service API",
    description="Сервис для размещения и управления объявлениями с аутентификацией и системой ролей",
    version="2.0.0"
)

SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2880
users_db = {}
ads_db = {}
tokens_db = {}
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def get_password_hash(password: str) -> str:
    """Безопасное хеширование пароля с помощью bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    return pwd_context.verify(plain_password, hashed_password)

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)
    password: str = Field(..., min_length=6, max_length=72)


class UserPublic(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    created_at: datetime


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


class AdvertisementUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)
    author: Optional[str] = Field(None, min_length=1, max_length=100)


class AdvertisementPublic(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    price: float
    author: str
    owner_id: int
    created_at: datetime

def create_access_token(data: dict):
    """Создание JWT токена"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(username: str, password: str):
    """Аутентификация пользователя"""
    user = users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Получение текущего пользователя из токена"""
    token = credentials.credentials

    if token not in tokens_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный токен",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = tokens_db[token]
    user = users_db.get(username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

@app.get("/")
def root():
    return {
        "message": "Advertisement Service API",
        "docs": "/docs",
        "users_count": len(users_db),
        "ads_count": len(ads_db),
        "public_endpoints": [
            "POST /user - Создать пользователя",
            "GET /user/{id} - Получить пользователя",
            "GET /advertisement/{id} - Получить объявление",
            "GET /advertisement - Поиск объявлений",
            "POST /login - Аутентификация"
        ],
        "protected_endpoints": [
            "POST /advertisement - Создать объявление",
            "PATCH /user/{id} - Обновить пользователя",
            "DELETE /user/{id} - Удалить пользователя",
            "PATCH /advertisement/{id} - Обновить объявление",
            "DELETE /advertisement/{id} - Удалить объявление"
        ]
    }

@app.post("/login", response_model=Token)
def login(login_data: LoginRequest):
    """Аутентификация пользователя"""
    user = authenticate_user(login_data.username, login_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = str(uuid.uuid4())
    tokens_db[token] = login_data.username
    access_token = create_access_token(
        data={"sub": user["username"], "user_id": user["id"], "role": user["role"]}
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/user", response_model=UserPublic)
def create_user(user: UserCreate):
    """Создание нового пользователя"""
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Пользователь с таким именем уже существует"
        )

    for existing_user in users_db.values():
        if existing_user["email"] == user.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Пользователь с таким email уже существует"
            )

    user_id = len(users_db) + 1
    users_db[user.username] = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "role": "user",
        "created_at": datetime.now()
    }

    return users_db[user.username]


@app.get("/user/{user_id}", response_model=UserPublic)
def get_user(user_id: int):
    """Получение пользователя по ID"""
    for user in users_db.values():
        if user["id"] == user_id:
            return user
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Пользователь не найден"
    )

@app.patch("/user/{user_id}", response_model=UserPublic)
def update_user(
        user_id: int,
        user_update: dict,
        current_user: dict = Depends(get_current_user)
):
    """Обновление пользователя"""
    target_user = None
    for user in users_db.values():
        if user["id"] == user_id:
            target_user = user
            break

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    if current_user["role"] != "admin" and current_user["id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для обновления этого пользователя"
        )

    allowed_fields = ["email", "full_name"]
    for field in allowed_fields:
        if field in user_update:
            target_user[field] = user_update[field]

    if "password" in user_update:
        target_user["hashed_password"] = get_password_hash(user_update["password"])
    users_db[target_user["username"]] = target_user

    return target_user


@app.delete("/user/{user_id}")
def delete_user(
        user_id: int,
        current_user: dict = Depends(get_current_user)
):
    """Удаление пользователя"""
    target_user = None
    target_username = None
    for username, user in users_db.items():
        if user["id"] == user_id:
            target_user = user
            target_username = username
            break

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    if current_user["role"] != "admin" and current_user["id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для удаления этого пользователя"
        )

    ads_to_delete = []
    for ad_id, ad in ads_db.items():
        if ad["owner_id"] == user_id:
            ads_to_delete.append(ad_id)

    for ad_id in ads_to_delete:
        del ads_db[ad_id]
    del users_db[target_username]
    tokens_to_delete = []
    for token, username in tokens_db.items():
        if username == target_username:
            tokens_to_delete.append(token)

    for token in tokens_to_delete:
        del tokens_db[token]

    return {"message": "Пользователь успешно удален"}

@app.get("/advertisement/{advertisement_id}", response_model=AdvertisementPublic)
def get_advertisement(advertisement_id: int):
    """Получение объявления по ID"""
    ad = ads_db.get(advertisement_id)
    if not ad:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Объявление не найдено"
        )
    return ad


@app.get("/advertisement", response_model=List[AdvertisementPublic])
def search_advertisements(
        title: Optional[str] = Query(None, description="Поиск по заголовку"),
        description: Optional[str] = Query(None, description="Поиск по описанию"),
        price_min: Optional[float] = Query(None, description="Минимальная цена", ge=0),
        price_max: Optional[float] = Query(None, description="Максимальная цена", ge=0),
        author: Optional[str] = Query(None, description="Поиск по автору"),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000)
):
    """Поиск объявлений"""
    results = []

    for ad in ads_db.values():
        if title and title.lower() not in ad["title"].lower():
            continue
        if description and ad["description"] and description.lower() not in ad["description"].lower():
            continue
        if price_min is not None and ad["price"] < price_min:
            continue
        if price_max is not None and ad["price"] > price_max:
            continue
        if author and author.lower() not in ad["author"].lower():
            continue

        results.append(ad)

    return results[skip:skip + limit]

@app.post("/advertisement", response_model=AdvertisementPublic)
def create_advertisement(
        advertisement: AdvertisementCreate,
        current_user: dict = Depends(get_current_user)
):
    """Создание нового объявления"""
    if current_user["role"] not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для создания объявления"
        )

    ad_id = len(ads_db) + 1
    ads_db[ad_id] = {
        "id": ad_id,
        "title": advertisement.title,
        "description": advertisement.description,
        "price": advertisement.price,
        "author": advertisement.author,
        "owner_id": current_user["id"],
        "created_at": datetime.now()
    }

    return ads_db[ad_id]


@app.patch("/advertisement/{advertisement_id}", response_model=AdvertisementPublic)
def update_advertisement(
        advertisement_id: int,
        advertisement_update: AdvertisementUpdate,
        current_user: dict = Depends(get_current_user)
):
    """Обновление объявления"""
    ad = ads_db.get(advertisement_id)
    if not ad:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Объявление не найдено"
        )

    if current_user["role"] != "admin" and current_user["id"] != ad["owner_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для обновления этого объявления"
        )

    update_data = advertisement_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            ad[field] = value
    ads_db[advertisement_id] = ad

    return ad


@app.delete("/advertisement/{advertisement_id}")
def delete_advertisement(
        advertisement_id: int,
        current_user: dict = Depends(get_current_user)
):
    """Удаление объявления"""
    ad = ads_db.get(advertisement_id)
    if not ad:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Объявление не найдено"
        )

    if current_user["role"] != "admin" and current_user["id"] != ad["owner_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для удаления этого объявления"
        )

    del ads_db[advertisement_id]

    return {"message": "Объявление успешно удалено"}

@app.post("/admin/create-admin")
def create_admin_user():
    """Создание администратора для тестирования"""
    if "admin" in users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Администратор уже существует"
        )

    users_db["admin"] = {
        "id": len(users_db) + 1,
        "username": "admin",
        "email": "admin@example.com",
        "full_name": "Administrator",
        "hashed_password": get_password_hash("admin123"),
        "role": "admin",
        "created_at": datetime.now()
    }

    return {"message": "Администратор создан", "user": users_db["admin"]}


@app.get("/admin/users")
def get_all_users(current_user: dict = Depends(get_current_user)):
    """Получение всех пользователей (только для администраторов)"""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав"
        )

    return list(users_db.values())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)