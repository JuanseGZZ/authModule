# models/base.py
from datetime import datetime
from typing import Optional

#domain -> son las clases que uso en el back

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
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import JSONB

Base = declarative_base()

# orm -> son las clases que uso para mandarle al orm que haga la query, o lo que me devuelve el orm prese

class UserORM(Base):
    __tablename__ = "app_user"

    id = Column(Integer, primary_key=True)
    mail = Column(String, nullable=False)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    aes_encripter = Column(String, nullable=False)
    created = Column(DateTime, default=datetime.utcnow, nullable=False)

    public = relationship("UserPublicDataORM", uselist=False, back_populates="user", cascade="all, delete-orphan")
    protected = relationship("UserProtectedDataORM", uselist=False, back_populates="user", cascade="all, delete-orphan")


class UserPublicDataORM(Base):
    __tablename__ = "user_public_data"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("app_user.id"), unique=True, nullable=False)

    nombre = Column(String)
    avatar_url = Column(String)
    bio = Column(String)

    user = relationship("UserORM", back_populates="public")


class UserProtectedDataORM(Base):
    __tablename__ = "user_protected_data"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("app_user.id"), unique=True, nullable=False)

    metricas = Column(JSONB)
    tokens = Column(JSONB)
    preferencias = Column(JSONB)

    user = relationship("UserORM", back_populates="protected")


#mapping -> es para pasar de clase orm a nuestras clases o viseversa
def orm_to_domain(db_user: UserORM) -> User:
    dp = None
    dprot = None

    if db_user.public:
        dp = DataPublic(
            nombre=db_user.public.nombre,
            avatar_url=db_user.public.avatar_url,
            bio=db_user.public.bio,
        )

    if db_user.protected:
        dprot = DataProtected(
            metricas=db_user.protected.metricas,
            tokens=db_user.protected.tokens,
            preferencias=db_user.protected.preferencias,
        )

    return User(
        mail=db_user.mail,
        username=db_user.username,
        password=db_user.password,
        is_admin=db_user.is_admin,
        aesEncriper=db_user.aes_encripter,
        datapublic=dp,
        dataprotected=dprot,
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

    # Public
    if db_user.public is None:
        db_user.public = UserPublicDataORM()
    db_user.public.nombre = user.datapublic.nombre
    db_user.public.avatar_url = user.datapublic.avatar_url
    db_user.public.bio = user.datapublic.bio

    # Protected
    if db_user.protected is None:
        db_user.protected = UserProtectedDataORM()
    db_user.protected.metricas = user.dataprotected.metricas
    db_user.protected.tokens = user.dataprotected.tokens
    db_user.protected.preferencias = user.dataprotected.preferencias

    return db_user
