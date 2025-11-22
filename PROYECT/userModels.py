# models/base.py
from datetime import datetime
from typing import Optional

class DataPublic:
    """Datos visibles para todo público."""
    def __init__(self, nombre: Optional[str] = None,
                 avatar_url: Optional[str] = None,
                 bio: Optional[str] = None):
        self.nombre = nombre
        self.avatar_url = avatar_url
        self.bio = bio

    def __repr__(self):
        return f"<DataPublic nombre={self.nombre!r}>"
    
    def to_dict(self):
        return {
            "nombre": self.nombre,
            "avatar_url": self.avatar_url,
            "bio": self.bio,
        }

    @classmethod
    def from_dict(cls, data: dict | None):
        data = data or {}
        return cls(
            nombre=data.get("nombre"),
            avatar_url=data.get("avatar_url"),
            bio=data.get("bio"),
        )

class DataProtected:
    """Datos cifrados con el KMS, visibles por módulos del sistema."""
    def __init__(self, metricas: Optional[str] = None,
                 tokens: Optional[str] = None,
                 preferencias: Optional[str] = None):
        self.metricas = metricas
        self.tokens = tokens
        self.preferencias = preferencias

    def __repr__(self):
        return f"<DataProtected metricas={self.metricas!r}>"

    def to_dict(self):
        return {
            "metricas": self.metricas,
            "tokens": self.tokens,
            "preferencias": self.preferencias,
        }

    @classmethod
    def from_dict(cls, data: dict | None):
        data = data or {}
        return cls(
            metricas=data.get("metricas"),
            tokens=data.get("tokens"),
            preferencias=data.get("preferencias"),
        )

class User:
    """Modelo de usuario base del framework."""
    def __init__(self,
                 datapublic: Optional[DataPublic] = None,
                 dataprotected: Optional[DataProtected] = None,
                 mail: str = "",
                 username: str = "",
                 password: str = "",
                 is_admin: bool = False,
                 aesEncriper: str = ""):

        self.datapublic = datapublic or DataPublic()
        self.dataprotected = dataprotected or DataProtected()
        self.mail = mail
        self.username = username
        self.password = password
        self.created = datetime.utcnow()
        self.is_admin = is_admin
        self.aesEncriper = aesEncriper

    def __repr__(self):
        return f"<User username={self.username!r} mail={self.mail!r} admin={self.is_admin}>"


# models_orm.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class UserORM(Base):
    __tablename__ = "app_user"

    id = Column(Integer, primary_key=True)
    mail = Column(String, nullable=False)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    aes_encripter = Column(String, nullable=False)
    created = Column(DateTime, default=datetime.utcnow, nullable=False)

    data_public = Column(JSONB, nullable=False, default=dict)
    data_protected = Column(JSONB, nullable=False, default=dict)

def orm_to_domain(db_user: UserORM) -> User:
    return User(
        mail=db_user.mail,
        username=db_user.username,
        password=db_user.password,
        is_admin=db_user.is_admin,
        aesEncriper=db_user.aes_encripter,
        datapublic=DataPublic.from_dict(db_user.data_public),
        dataprotected=DataProtected.from_dict(db_user.data_protected),
    )

def domain_to_orm(user: User, db_user: UserORM | None = None) -> UserORM:
    if db_user is None:
        db_user = UserORM()

    db_user.mail = user.mail
    db_user.username = user.username
    db_user.password = user.password
    db_user.is_admin = user.is_admin
    db_user.aes_encripter = user.aesEncriper
    db_user.created = user.created

    db_user.data_public = user.datapublic.to_dict()
    db_user.data_protected = user.dataprotected.to_dict()

    return db_user