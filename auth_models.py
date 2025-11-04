# from sqlalchemy import Column, Integer, String, Boolean
# from sqlalchemy.ext.declarative import declarative_base
# from pydantic import BaseModel
# from typing import Optional
#
# Base = declarative_base()
#
#
# # SQLAlchemy модель пользователя
# class DBUser(Base):
#     __tablename__ = "users"
#
#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String, unique=True, index=True, nullable=False)
#     hashed_password = Column(String, nullable=False)
#     role = Column(String, nullable=False)  # 'admin' или 'user'
#     is_active = Column(Boolean, default=True)
#
#
# # Pydantic модели для API
# class UserBase(BaseModel):
#     username: str
#     role: str
#
#
# class UserCreate(BaseModel):
#     username: str
#     password: str
#
#
# class UserResponse(UserBase):
#     id: int
#     is_active: bool
#
#     class Config:
#         from_attributes = True
#
#
# class Token(BaseModel):
#     access_token: str
#     token_type: str
#     username: str
#     role: str
#
#
# class TokenData(BaseModel):
#     username: Optional[str] = None
#     role: Optional[str] = None

from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from typing import Optional

Base = declarative_base()

# SQLAlchemy модель пользователя
class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # 'admin', 'manager' или 'user'
    is_active = Column(Boolean, default=True)

# Pydantic модели для API
class UserBase(BaseModel):
    username: str
    role: str

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# Дополнительные модели для прав
class UserPermissions(BaseModel):
    can_manage_executors: bool
    can_manage_cases: bool
    can_view_executors: bool
    role: str

