from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional


class AdvertisementBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    price: float = Field(..., gt=0)
    author: str = Field(..., min_length=1, max_length=100)


class AdvertisementCreate(AdvertisementBase):
    pass


class AdvertisementUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)
    author: Optional[str] = Field(None, min_length=1, max_length=100)


class Advertisement(AdvertisementBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)