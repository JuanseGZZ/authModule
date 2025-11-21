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


class DataPrivate:
    """Datos sensibles cifrados con la contraseña del usuario."""
    def __init__(self, documento: Optional[str] = None,
                 datos_bancarios: Optional[str] = None,
                 direccion: Optional[str] = None):
        self.documento = documento
        self.datos_bancarios = datos_bancarios
        self.direccion = direccion

    def __repr__(self):
        return f"<DataPrivate documento={'***' if self.documento else None}>"


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
                 dataprivate: Optional[DataPrivate] = None,
                 dataprotected: Optional[DataProtected] = None,
                 mail: str = "",
                 username: str = "",
                 password: str = "",
                 is_admin: bool = False,
                 aesEncriper: str = ""):

        self.datapublic = datapublic or DataPublic()
        self.dataprivate = dataprivate or DataPrivate()
        self.dataprotected = dataprotected or DataProtected()
        self.mail = mail
        self.username = username
        self.password = password
        self.created = datetime.utcnow()
        self.is_admin = is_admin
        self.aesEncriper = aesEncriper

    def __repr__(self):
        return f"<User username={self.username!r} mail={self.mail!r} admin={self.is_admin}>"
