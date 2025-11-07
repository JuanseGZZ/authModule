# models/base.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class DataPublic(BaseModel):
    """Datos visibles para todo público."""
    nombre: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None


class DataPrivate(BaseModel):
    """Datos sensibles cifrados con la contraseña del usuario."""
    documento: Optional[str] = None
    datos_bancarios: Optional[str] = None
    direccion: Optional[str] = None


class DataProtected(BaseModel):
    """Datos cifrados con el KMS, visibles por módulos del sistema."""
    metricas: Optional[str] = None
    tokens: Optional[str] = None
    preferencias: Optional[str] = None


class User(BaseModel):
    """Modelo de usuario base del framework."""
    datapublic: DataPublic
    dataprivate: DataPrivate
    dataprotected: DataProtected
    mail: str
    username: str
    password: str
    created: datetime
    is_admin: bool = False
