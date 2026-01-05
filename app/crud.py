from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import Optional, Dict, Any
from . import models, schemas


def create_advertisement(db: Session, advertisement: schemas.AdvertisementCreate):
    db_advertisement = models.Advertisement(**advertisement.model_dump())
    db.add(db_advertisement)
    db.commit()
    db.refresh(db_advertisement)
    return db_advertisement


def get_advertisement(db: Session, advertisement_id: int):
    return db.query(models.Advertisement).filter(models.Advertisement.id == advertisement_id).first()


def update_advertisement(db: Session, advertisement_id: int, advertisement_update: schemas.AdvertisementUpdate):
    db_advertisement = get_advertisement(db, advertisement_id)
    if db_advertisement:
        update_data = advertisement_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_advertisement, field, value)
        db.commit()
        db.refresh(db_advertisement)
    return db_advertisement


def delete_advertisement(db: Session, advertisement_id: int):
    db_advertisement = get_advertisement(db, advertisement_id)
    if db_advertisement:
        db.delete(db_advertisement)
        db.commit()
        return True
    return False


def search_advertisements(
        db: Session,
        title: Optional[str] = None,
        description: Optional[str] = None,
        price_min: Optional[float] = None,
        price_max: Optional[float] = None,
        author: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
):
    query = db.query(models.Advertisement)

    filters = []

    if title:
        filters.append(models.Advertisement.title.ilike(f"%{title}%"))
    if description:
        filters.append(models.Advertisement.description.ilike(f"%{description}%"))
    if price_min is not None:
        filters.append(models.Advertisement.price >= price_min)
    if price_max is not None:
        filters.append(models.Advertisement.price <= price_max)
    if author:
        filters.append(models.Advertisement.author.ilike(f"%{author}%"))

    if filters:
        query = query.filter(and_(*filters))

    return query.offset(skip).limit(limit).all()