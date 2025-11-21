from DBController import PostgresDB
from DBController import RedisDB
from typing import Dict, Any
from userModels import User
from datetime import datetime
import bcrypt

from KMS import KMS, cifrar_con_user_aes, descifrar_con_user_aes

kms = KMS()

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")

# para gestionar peticiones a db y que te devuelva objets user
class userRepository:

    #Lista de usuarios registrados simulada
    usuarios: list[User] = []
    # Simulación de sesiones JWT (stateless)
    sesionesRedisJWT: list[Dict[str, str]] = []  # [{"email": ..., "refreshToken": ..., "until": }]
    # Simulación de sesiones stateful (sólo si está habilitado)
    sesionesRedisStateFull: Dict[str, Dict[str, str]] = {}  # {"email": {"user_id":int,"aesKey": str, "refreshToken": str, "until": str}}

    def __init__(self):
        pass

    @staticmethod
    def crearUsuario(email: str, username: str, password: str, is_admin: bool = False) -> User:
        for usuario in userRepository.usuarios:
            if usuario.mail == email:
                return "mail esta en uso"
            
        keys = kms.crearKeyUser()

        encripted = keys.get("encrypted_b64")
        #print("Non encripted key, in fact encripter key:", keys.get("plain_b64"))
        #print("must be the same as non encripted",kms.decifrarKey(encripted))

        # Crear usuario sólo con los datos base
        usuario = User(
            mail=email,
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
    print("Email:", nuevo.mail)
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

test_creacion_usuario()
