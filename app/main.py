from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from . import crud, models, schemas, database
from .database import engine
import uvicorn

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Advertisement Service API",
    description="Сервис для размещения объявлений купли/продажи",
    version="1.0.0"
)

@app.post("/advertisement", response_model=schemas.Advertisement)
def create_advertisement(
    advertisement: schemas.AdvertisementCreate,
    db: Session = Depends(database.get_db)
):
    """Создание нового объявления"""
    return crud.create_advertisement(db=db, advertisement=advertisement)

@app.get("/advertisement/{advertisement_id}", response_model=schemas.Advertisement)
def read_advertisement(
    advertisement_id: int,
    db: Session = Depends(database.get_db)
):
    """Получение объявления по ID"""
    db_advertisement = crud.get_advertisement(db, advertisement_id=advertisement_id)
    if db_advertisement is None:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    return db_advertisement

@app.patch("/advertisement/{advertisement_id}", response_model=schemas.Advertisement)
def update_advertisement(
    advertisement_id: int,
    advertisement_update: schemas.AdvertisementUpdate,
    db: Session = Depends(database.get_db)
):
    """Обновление объявления"""
    db_advertisement = crud.update_advertisement(db, advertisement_id, advertisement_update)
    if db_advertisement is None:
        raise HTTPException(status_code=404, detail="Объявление не найдено")
    return db_advertisement

@app.delete("/advertisement/{advertisement_id}")
def delete_advertisement(
    advertisement_id: int,
    db: Session = Depends(database.get_db)
):
    """Удаление объявления"""
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
    """Поиск объявлений по различным параметрам"""
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

@app.get("/")
def read_root():
    return {
        "message": "Advertisement Service API",
        "docs": "/docs",
        "redoc": "/redoc"
    }