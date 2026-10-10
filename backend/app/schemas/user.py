from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


Role = Literal["admin", "analyst", "viewer"]


class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: EmailStr
    role: Role = "viewer"


class UserCreate(UserBase):
    password: str = Field(min_length=10, max_length=128)


class UserUpdate(BaseModel):
    role: Role | None = None
    email: EmailStr | None = None


class UserOut(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=10, max_length=128)

