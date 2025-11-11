from DBController import PostgresDB
from DBController import RedisDB
from typing import Dict, Any
from userModels import User
from datetime import datetime

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
    def crearUsuario(email:str, username:str, password:str) -> User:
        for usuario in userRepository.usuarios:
            if usuario.mail == email:
                return "mail esta en uso"
            

        usuario = User(email,username,password)
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