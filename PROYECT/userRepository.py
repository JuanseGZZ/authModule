from userModels import User
import bcrypt

from KMS import cifrar_con_user_aes, descifrar_con_user_aes

from KMSController import KMSController as kms


# aesky = kms.decifrarKey(nuevo.aesEncriper)
# cifrar_con_user_aes(aeskey,datoACifrar)
# descifrar_con_user_aes(aeskey,datoADescifrar)

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


from sessions import sesionesRedisJWT as SJWT, sesionesRedisStateFull as SSF

# para gestionar peticiones a db y que te devuelva objets user
class userRepository:

    #Lista de usuarios registrados simulada
    usuarios: list[User] = []

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

    # -------------------------------- SESIONES
    # ---------------- SJWT
    @staticmethod
    def guardar_sesion_refresh(email: str, refresh_token: str) -> None:
        # class implementation
        SJWT(email=email,refreshtoken=refresh_token)
    @staticmethod
    def eliminar_sesion_refresh(refresh_token: str) -> bool:
        return SJWT.delete(refresh_token=refresh_token)
    @staticmethod
    def refresh_valido(refresh_token: str) -> bool:
        return SJWT.refresh_valido(refresh_token=refresh_token)
    @staticmethod
    def checkRefreshToken(email:str, refreshToken:str) -> bool:
        return SJWT.check(email=email, refresh_token=refreshToken)
    # ----------------- StateFull
    @staticmethod
    def guardar_sesion_statefull(user_id:str, aes_key:str, refresh_token:str):
        # class implementation
        SSF(user_id=user_id,aesKey=aes_key,refreshToken=refresh_token)
    @staticmethod
    def eliminar_sesion_statefull(user_id: str, aes_key: str):
        return SSF.delete(user_id=user_id,aes_key=aes_key)
    @staticmethod
    def get_statefull_session(user_id: str):
        return SSF.get(user_id)
    @staticmethod
    def checkSFToken(refresh_token: str, id_user: str) -> bool: # cambiar que el id sea igual al refresh, por que el aes que devuelve el deciframiento con el aes del id, sean iguales las aes, para validar que el paket no fue adulterado
        return SSF.check(refresh_token=refresh_token, user_id=id_user)
    

#/---------------------------------------/

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

test_creacion_usuario()
