from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import Optional, Dict, Any, List
from . import models, schemas, auth

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = get_user_by_username(db, username=user.username)
    if db_user:
        return None
    
    db_user_email = get_user_by_email(db, email=user.email)
    if db_user_email:
        return None

    hashed_password = auth.get_password_hash(user.password)

    db_user = models.User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        role=user.role
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user(db: Session, user_id: int, user_update: schemas.UserUpdate):
    db_user = get_user(db, user_id)
    if db_user:
        update_data = user_update.model_dump(exclude_unset=True)

        if "password" in update_data:
            update_data["hashed_password"] = auth.get_password_hash(update_data.pop("password"))
        
        for field, value in update_data.items():
            setattr(db_user, field, value)
        
        db.commit()
        db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    db_user = get_user(db, user_id)
    if db_user:
        db.query(models.Advertisement).filter(models.Advertisement.owner_id == user_id).delete()

        db.delete(db_user)
        db.commit()
        return True
    return False

def create_advertisement(db: Session, advertisement: schemas.AdvertisementCreate, owner_id: int):
    db_advertisement = models.Advertisement(**advertisement.model_dump(), owner_id=owner_id)
    db.add(db_advertisement)
    db.commit()
    db.refresh(db_advertisement)
    return db_advertisement

def get_advertisement(db: Session, advertisement_id: int):
    return db.query(models.Advertisement).filter(models.Advertisement.id == advertisement_id).first()

def get_advertisements_by_owner(db: Session, owner_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.Advertisement).filter(
        models.Advertisement.owner_id == owner_id
    ).offset(skip).limit(limit).all()

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
    owner_id: Optional[int] = None,
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
    if owner_id is not None:
        filters.append(models.Advertisement.owner_id == owner_id)
    
    if filters:
        query = query.filter(and_(*filters))
    
    return query.offset(skip).limit(limit).all()
