from fastapi import FastAPI, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional, List, Annotated
from datetime import timedelta
from . import crud, models, schemas, database, auth
from .database import engine
import uvicorn


models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Advertisement Service API",
    description="Сервис для размещения объявлений купли/продажи с аутентификацией",
    version="2.0.0"
)


@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    login_data: schemas.LoginRequest,
    db: Session = Depends(database.get_db)
):
    """Аутентификация пользователя и получение токена"""
    user = auth.authenticate_user(db, login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "role": user.role
        },
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user", response_model=schemas.UserPublic)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db)
):
    """Создание нового пользователя (публичный доступ)"""

    if user.role == "admin":
        user.role = "user"
    
    db_user = crud.create_user(db, user)
    if db_user is None:
        raise HTTPException(
            status_code=400,
            detail="Пользователь с таким именем или email уже существует"
        )
    return db_user

@app.get("/user/{user_id}", response_model=schemas.UserPublic)
def read_user(
    user_id: int,
    db: Session = Depends(database.get_db)
):
    """Получение пользователя по ID (публичный доступ)"""
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return db_user

@app.patch("/user/{user_id}", response_model=schemas.UserPublic)
def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_user_or_admin)
):
    """Обновление пользователя"""

    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для обновления этого пользователя"
        )
    

    db_user = crud.get_user(db, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    

    if current_user.role != "admin" and user_update.role:
        user_update.role = None
    
    return crud.update_user(db, user_id, user_update)

@app.delete("/user/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_user_or_admin)
):
    """Удаление пользователя"""

    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для удаления этого пользователя"
        )
    

    db_user = crud.get_user(db, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    crud.delete_user(db, user_id)
    return {"message": "Пользователь успешно удален"}


@app.post("/advertisement", response_model=schemas.Advertisement)
def create_advertisement(
    advertisement: schemas.AdvertisementCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Создание нового объявления (требуется аутентификация)"""

    if current_user.role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для создания объявления"
        )
    
    return crud.create_advertisement(
        db=db, 
        advertisement=advertisement, 
        owner_id=current_user.id
    )

@app.get("/advertisement/{advertisement_id}", response_model=schemas.Advertisement)
def read_advertisement(
    advertisement_id: int,
    db: Session = Depends(database.get_db)
):
    """Получение объявления по ID (публичный доступ)"""
    db_advertisement = crud.get_advertisement(db, advertisement_id=advertisement_id)
    if db_advertisement is None:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    return db_advertisement

@app.patch("/advertisement/{advertisement_id}", response_model=schemas.Advertisement)
def update_advertisement(
    advertisement_id: int,
    advertisement_update: schemas.AdvertisementUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Обновление объявления"""

    db_advertisement = crud.get_advertisement(db, advertisement_id)
    if db_advertisement is None:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    

    if current_user.role != "admin" and current_user.id != db_advertisement.owner_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для обновления этого объявления"
        )
    
    return crud.update_advertisement(db, advertisement_id, advertisement_update)

@app.delete("/advertisement/{advertisement_id}")
def delete_advertisement(
    advertisement_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Удаление объявления"""

    db_advertisement = crud.get_advertisement(db, advertisement_id)
    if db_advertisement is None:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    

    if current_user.role != "admin" and current_user.id != db_advertisement.owner_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для удаления этого объявления"
        )
    
    success = crud.delete_advertisement(db, advertisement_id)
    if not success:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    return {"message": "Объявление успешно удалено"}

@app.get("/advertisement", response_model=List[schemas.Advertisement])
def search_advertisements(
    title: Optional[str] = Query(None, description="Поиск по заголовку"),
    description: Optional[str] = Query(None, description="Поиск по описанию"),
    price_min: Optional[float] = Query(None, description="Минимальная цена", ge=0),
    price_max: Optional[float] = Query(None, description="Максимальная цена", ge=0),
    author: Optional[str] = Query(None, description="Поиск по автору"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(database.get_db)
):
    """Поиск объявлений по различным параметрам (публичный доступ)"""
    return crud.search_advertisements(
        db=db,
        title=title,
        description=description,
        price_min=price_min,
        price_max=price_max,
        author=author,
        skip=skip,
        limit=limit
    )


@app.get("/admin/users", response_model=List[schemas.UserPublic])
def get_all_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_admin)
):
    """Получение всех пользователей (только для администраторов)"""
    return crud.get_users(db, skip=skip, limit=limit)

@app.get("/admin/advertisements", response_model=List[schemas.Advertisement])
def get_all_advertisements(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_admin)
):
    """Получение всех объявлений (только для администраторов)"""
    return crud.search_advertisements(db=db, skip=skip, limit=limit)


@app.get("/me", response_model=schemas.UserPublic)
def read_current_user(
    current_user: models.User = Depends(auth.get_current_user)
):
    """Получение информации о текущем пользователе"""
    return current_user

@app.get("/me/advertisements", response_model=List[schemas.Advertisement])
def read_user_advertisements(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Получение объявлений текущего пользователя"""
    return crud.get_advertisements_by_owner(
        db=db,
        owner_id=current_user.id,
        skip=skip,
        limit=limit
    )

@app.get("/")
def read_root():
    return {
        "message": "Advertisement Service API v2.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "public_endpoints": [
            "POST /user - Создание пользователя",
            "GET /user/{id} - Получение пользователя",
            "GET /advertisement/{id} - Получение объявления",
            "GET /advertisement - Поиск объявлений",
            "POST /login - Аутентификация"
        ],
        "protected_endpoints": [
            "GET /me - Информация о текущем пользователе",
            "GET /me/advertisements - Мои объявления",
            "POST /advertisement - Создание объявления",
            "PATCH /advertisement/{id} - Обновление моего объявления",
            "DELETE /advertisement/{id} - Удаление моего объявления"
        ],
        "admin_endpoints": [
            "GET /admin/users - Все пользователи",
            "GET /admin/advertisements - Все объявления"
        ]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
