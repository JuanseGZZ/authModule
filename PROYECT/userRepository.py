import os
from DBController import PostgresDB
from DBController import RedisDB
from typing import Dict, Any
from userModels import User
from datetime import datetime, timedelta, timezone
import bcrypt

from KMS import KMS, cifrar_con_user_aes, descifrar_con_user_aes

kms = KMS()

# para los dias del refresh
JWT_REFRESH_TTL_DAYS = int(os.getenv("JWT_REFRESH_TTL_DAYS", "30"))

# aesky = kms.decifrarKey(nuevo.aesEncriper)
# cifrar_con_user_aes(aeskey,datoACifrar)
# descifrar_con_user_aes(aeskey,datoADescifrar)

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

# para gestionar peticiones a db y que te devuelva objets user
class userRepository:

    #Lista de usuarios registrados simulada
    usuarios: list[User] = []
    # Simulación de sesiones JWT (stateless)
    sesionesRedisJWT: Dict[str, Dict[str, Any]] = {}  # [{"email": ..., "refreshToken": ..., "until": }]
    # Simulación de sesiones stateful (sólo si está habilitado)
    sesionesRedisStateFull: Dict[str, Dict[str, str]] = {}  # {"email": {"user_id":int,"aesKey": str, "refreshToken": str, "until": str}}

    def __init__(self):
        pass

    @staticmethod
    def crearUsuario(email: str, username: str, password: str, is_admin: bool = False) -> User:
        for usuario in userRepository.usuarios:
            if usuario.mail == email:
                return "mail esta en uso"
            
        keys = kms.crearKeyUser() #unica vez cuando se crea

        encripted = keys.get("encrypted_b64")
        encripter = keys.get("plain_b64")
        #print("Non encripted key, in fact encripter key:", keys.get("plain_b64"))
        #print("must be the same as non encripted",kms.decifrarKey(encripted))

        # Crear usuario sólo con los datos base
        usuario = User(
            mail=cifrar_con_user_aes(encripter,email),
            username=username,
            password=hash_password(password),
            is_admin=is_admin,
            aesEncriper=encripted # es la clave que encripta todo en la database
        )

        #va a db, en este caso aca por el momenot
        userRepository.usuarios.append(usuario)
        return usuario
    
    @staticmethod
    def checkRefreshToken(user:User, refreshToken:str) -> bool: # es horrible la forma de hacerse esto pero despues va a ser por db asi que nt
        for sesion in userRepository.sesionesRedisJWT:
            if sesion.get("email") ==  user.mail:
                if sesion.get("refreshToken") == refreshToken:
                    if sesion.get("until") > datetime.utcnow():
                        return True
        return False
    
    @staticmethod
    def checkSFToken(user:User, id_user):
        print("cheking")

    @staticmethod
    def getUser(email:str,username:str,password:str):
        print("trae usuario")

    @staticmethod
    def updateUserOnDB(user:User):
        print("Updatea el objeto en dbs")

    @staticmethod
    def getPrivateData(user:User,password:str,dataName:str):
        print("tae un paramepro protegido por password, usa dataname para decir cual")

    @staticmethod
    def guardar_sesion_refresh(email: str, refresh_token: str) -> None:
        """
        Guarda la sesión de refresh ligada al email.
        until = ahora + JWT_REFRESH_TTL_DAYS (en días).
        """
        until_dt = _now_utc() + timedelta(days=JWT_REFRESH_TTL_DAYS)
        # lo podés guardar como datetime o ISO, según cómo lo vayas a leer
        userRepository.sesionesRedisJWT[email] = {
            "refreshToken": refresh_token,
            "until": until_dt,    # o until_dt.isoformat() si preferís string
        }

    @staticmethod
    def refresh_valido(email: str, refresh_token: str) -> bool:
        ses = userRepository.sesionesRedisJWT.get(email)
        if not ses:
            return False
        if ses["refreshToken"] != refresh_token:
            return False
        return _now_utc() < ses["until"]


def test_creacion_usuario():
    print("=== TEST CREAR USUARIO ===")
    repo = userRepository()
    nuevo = repo.crearUsuario(
        email="test@example.com",
        username="tester",
        password="1234"
    )

    encripterAes = kms.decifrarKey(nuevo.aesEncriper)

    # ---- DATOS DE TEST (public, private, protected) ----
    # públicos
    nuevo.datapublic.nombre = "tester"
    nuevo.datapublic.avatar_url = f"https://example.com/avatars/{"tester"}"
    nuevo.datapublic.bio = "Bio de prueba para el usuario."

    # protegidos (cifrados con KMS en la implementación real)
    nuevo.dataprotected.metricas = cifrar_con_user_aes(encripterAes,"")          # JSON de métricas de ejemplo
    nuevo.dataprotected.tokens = cifrar_con_user_aes(encripterAes,"token_prueba")
    nuevo.dataprotected.preferencias = cifrar_con_user_aes(encripterAes,'{"theme": "dark"}')

    if isinstance(nuevo, str):
        print("Error:", nuevo)
        return
    print("Usuario creado correctamente:\n")
    print("Email:", descifrar_con_user_aes(encripterAes,nuevo.mail))
    print("Username:", nuevo.username)
    print("Password:",nuevo.password)
    print("AesEncripted:",nuevo.aesEncriper)
    print("Admin:", nuevo.is_admin)
    print("Fecha creación:", nuevo.created)
    print("\n--- DATA PUBLICA ---")
    print("Nombre:", nuevo.datapublic.nombre)
    print("Avatar URL:", nuevo.datapublic.avatar_url)
    print("Bio:", nuevo.datapublic.bio)
    print("\n--- DATA PROTEGIDA ---")
    print("Métricas:", descifrar_con_user_aes(encripterAes,nuevo.dataprotected.metricas))
    print("Tokens:", descifrar_con_user_aes(encripterAes,nuevo.dataprotected.tokens))
    print("Preferencias:", nuevo.dataprotected.preferencias)
    print("\nLISTA DE USUARIOS EN REPO:", len(userRepository.usuarios))
    print("=================================\n")

#test_creacion_usuario()
