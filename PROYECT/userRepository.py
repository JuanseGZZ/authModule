import os
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
    #pasar a clases estas listas, porque luego simplemente en vez de que la funcion guardar lo meta en un array en memoria, lo mande a db por el orm.

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
    def checkRefreshToken(email:str, refreshToken:str) -> bool:
            ses = userRepository.sesionesRedisJWT.get(email)
            if not ses:
                return False

            if ses["refreshToken"] != refreshToken:
                return False

            return _now_utc() < ses["until"]
    
    @staticmethod
    def checkSFToken(refresh_token: str, id_user: str) -> bool: # cambiar que el id sea igual al refresh, por que el aes que devuelve el deciframiento con el aes del id, sean iguales las aes, para validar que el paket no fue adulterado
        """
        Verifica la sesión stateful:
        - Que exista entrada para id_user
        - Que el refresh_token coincida
        - Que la sesión no esté vencida (until)
        """
        ses = userRepository.sesionesRedisStateFull.get(id_user)
        if not ses:
            return False

        if ses.get("refreshToken") != refresh_token:
            return False

        until = ses.get("until")
        # puede estar guardado como datetime o como ISO string
        if isinstance(until, str):
            try:
                # soportar formato con Z al final
                if until.endswith("Z"):
                    until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
                else:
                    until_dt = datetime.fromisoformat(until)
            except ValueError:
                return False
        else:
            until_dt = until

        return _now_utc() < until_dt

    @staticmethod
    def getUser(email: str | None, username: str | None, password: str) -> User | None:
        """
        Busca un usuario por:
        - email (desencriptando el mail con su aesEncriper), o
        - username (en claro),
        y valida que la password coincida (bcrypt).
        Devuelve el User o None si no hay match.
        """
        email = email or ""
        username = username or ""

        for usuario in userRepository.usuarios:
            ident_match = False

            # match por email (si lo mandaron)
            if email:
                try:
                    aes_plain_b64 = kms.decifrarKey(usuario.aesEncriper)
                    mail_claro = descifrar_con_user_aes(aes_plain_b64, usuario.mail)
                    if mail_claro == email:
                        ident_match = True
                except Exception:
                    # si algo falla al desencriptar este usuario, lo saltamos
                    pass

            # match por username (si lo mandaron)
            if username and usuario.username == username:
                ident_match = True

            if not ident_match:
                continue

            # validar password con bcrypt
            if bcrypt.checkpw(password.encode("utf-8"), usuario.password.encode("utf-8")):
                return usuario

        return None
    
    @staticmethod
    def create_user(email: str, username: str, password: str, is_admin: bool = False) -> User | str:
        from datetime import datetime
        from db import SessionLocal
        from userModels import UserORM, orm_to_domain, domain_to_orm,  User, DataPublic, DataProtected

        with SessionLocal() as db:
            if db.query(UserORM).filter_by(username=username).first():
                return "username esta en uso"

            keys = kms.crearKeyUser()
            encrypted_b64 = keys["encrypted_b64"]
            aes_plain_b64 = keys["plain_b64"]

            mail_cifrado = cifrar_con_user_aes(aes_plain_b64, email)
            pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            userDomain = User(
                mail=mail_cifrado,
                username=username,
                password=pwd_hash,
                is_admin=is_admin,
                aesEncriper=encrypted_b64,
                datapublic=DataPublic(),          # por ahora vacíos
                dataprotected=DataProtected(),    # después los vas seteando
            )

            db_user = domain_to_orm(userDomain)
            db.add(db_user)
            db.commit()
            db.refresh(db_user)

            return orm_to_domain(db_user)
    
    @staticmethod
    def get_user(email: str | None, username: str | None, password: str) -> User | None:
        from sqlalchemy.orm import joinedload
        from db import SessionLocal 
        from userModels import UserORM, orm_to_domain
        from KMS import KMS
        import bcrypt
    
        kms = KMS()
    
        email = email or ""
        username = username or ""
    
        with SessionLocal() as db:
        
            db_user = None
    
            # =============================
            # 1) Buscar por username
            # =============================
            if username:
                db_user = (
                    db.query(UserORM)
                        .options(
                            joinedload(UserORM.public),
                            joinedload(UserORM.protected),
                        )
                        .filter(UserORM.username == username)
                        .first()
                )
    
            # =============================
            # 2) Si no vino username, buscar por mail
            # (descifrando user por user)
            # =============================
            if not db_user and email:
                all_users = (
                    db.query(UserORM)
                        .options(
                            joinedload(UserORM.public),
                            joinedload(UserORM.protected),
                        )
                        .all()
                )
    
                for u in all_users:
                    try:
                        aes_plain = kms.decifrarKey(u.aes_encripter)
                        mail_claro = descifrar_con_user_aes(aes_plain, u.mail)
    
                        if mail_claro == email:
                            db_user = u
                            break
                        
                    except Exception:
                        continue
                    
            # =============================
            # Si no lo encontramos
            # =============================
            if not db_user:
                return None
    
            # =============================
            # 3) Validar password
            # =============================
            if not bcrypt.checkpw(password.encode("utf-8"), db_user.password.encode("utf-8")):
                return None
    
            # =============================
            # 4) Mapear ORM → dominio
            # =============================
            return orm_to_domain(db_user)

    @staticmethod
    def updateUserOnDB(user: User) -> bool:
        """
        Actualiza el usuario completo en la DB.
        Toma un User (dominio), busca su ORM por username, actualiza public+protected+core.
        """
        from db import SessionLocal
        from userModels import UserORM, domain_to_orm

        with SessionLocal() as db:
            # 1. Buscar user ORM por username
            db_user = (
                db.query(UserORM)
                  .filter(UserORM.username == user.username)
                  .first()
            )

            if not db_user:
                return False  # No existe el user

            # 2. Mapear del objeto dominio -> ORM existente
            domain_to_orm(user, db_user=db_user)

            # 3. Guardar cambios
            db.commit()
            db.refresh(db_user)

            return True

    @staticmethod
    def getDataUncypher(user: User, data: str) -> str | None:
        """
        Desencripta un dato del usuario usando la AES privada del usuario.
        - user: objeto de dominio User
        - data: dato cifrado en base64 (ciphertext+IV) que se quiere desencriptar
        Devuelve el dato en claro como str.
        """
        from KMS import KMS, descifrar_con_user_aes

        kms = KMS()

        if not data:
            return None

        try:
            # 1) AES en claro descifrada desde user.aesEncriper
            aes_plain_b64 = kms.decifrarKey(user.aesEncriper)

            # 2) Desencriptar el dato usando AES del usuario
            dato_claro = descifrar_con_user_aes(aes_plain_b64, data)

            return dato_claro

        except Exception as e:
            print("Error desencriptando dato:", e)
            return None

    @staticmethod
    def setDataCipher(user:User, data_claro:str):
        aes = kms.decifrarKey(user.aesEncriper)
        return cifrar_con_user_aes(aes, data_claro)

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
    def eliminar_sesion_refresh(refresh_token: str) -> bool:
        sesiones = userRepository.sesionesRedisJWT
    
        email_a_borrar = None
        for email, ses in sesiones.items():
            if ses.get("refreshToken") == refresh_token:
                email_a_borrar = email
                break
            
        if email_a_borrar is not None:
            del sesiones[email_a_borrar]
            return True
    
        return False
        

    @staticmethod
    def refresh_valido(refresh_token: str) -> bool:
        ses = None

        # localizar la sesión que tenga ese refresh_token
        for s in userRepository.sesionesRedisJWT.values():
            if s.get("refreshToken") == refresh_token:
                ses = s
                break

        if not ses:
            return False

        return _now_utc() < ses["until"]

    @staticmethod
    def guardar_sesion_statefull(user_id:str, aes_key:str, refresh_token:str, until_iso):
        userRepository.sesionesRedisStateFull[user_id] = {
            "aesKey": aes_key,
            "until": until_iso,
            "refreshToken": refresh_token,
        }

    @staticmethod
    def eliminar_sesion_statefull(user_id: str, aes_key: str):
        sesiones = userRepository.sesionesRedisStateFull

        # Verificar que exista el user_id
        if user_id not in sesiones:
            return False  # No existe

        # Verificar coincidencia de aesKey
        if sesiones[user_id].get("aesKey") == aes_key:
            del sesiones[user_id]
            return True  # Eliminado

        return False  # No machea



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
