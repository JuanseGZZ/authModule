# auth.py
import os
import uuid
from datetime import datetime, timedelta, timezone

# Importamos los módulos base del sistema de autenticación
from ensureKeys import ensure_keys
from PaketCipher import Packet
from accesToken import AccessToken
from refreshToken import RefreshToken
from KMS import KMS, descifrar_con_user_aes, cifrar_con_user_aes
from userRepository import userRepository as UR

from typing import Dict, Any

from userModels import User, Base

DEBUG = False

# Cargamos el flag desde .env
STATEFULL_ENABLED = os.getenv("STATEFULL_ENABLED", "false").lower() == "true"
STATEFULL_TOKEN_TIME_MIN = int(os.getenv("STATEFULL_TOKEN_TIME_MIN", "15"))


def init() -> None:
    """
    Inicializa el entorno de autenticación:
    - Verifica (o genera) las claves RSA y AES necesarias para el sistema.
    - Carga las variables de entorno (.env).
    - Informa las rutas de las claves creadas o encontradas.
    """
    from db import engine
    from userModels import Base

    Base.metadata.create_all(bind=engine)

    if DEBUG:
        print("🔑 Iniciando módulo de autenticación...")
    keys = ensure_keys()
    if DEBUG:
        print("✅ Claves verificadas o generadas correctamente.")
        print(f"RSA (enc) privada: {keys.ec_priv}")
        print(f"RSA (enc) pública : {keys.ec_pub}")
        print(f"RSA (sign) priv   : {keys.rsa_priv}")
        print(f"RSA (sign) pub    : {keys.rsa_pub}")
        print(f"AES master key    : {keys.aes_key}")

        print(f"STATEFULL_ENABLED = {STATEFULL_ENABLED}")
    if STATEFULL_ENABLED:
        global sesionesRedisStateFull
        sesionesRedisStateFull = {}
        if DEBUG:
            print("Sesiones stateful activadas (Redis simulado en memoria).")
    else:
        if DEBUG:
            print("Modo stateful deshabilitado — no se crearán sesiones persistentes.")

#funcs con stateful handshake, luego se hace api y el proyecto las hereda.
def register(request_json: Dict[str, Any]) -> Dict[str, str]:
    """
    Request: {"handshake_b64u": "<b64url(RSA-OAEP(JSON))>"}  // alias: "ciphertext_b64u"
    El JSON interno del handshake debe traer: {"username","password","email","aeskey"}.
    Response: {"iv","ciphertext"}  // AES-GCM sobre {rt, at, data, user_id}
    """
    # 1) Extraer blob RSA del request (aceptamos dos alias por conveniencia) <<<<<<<<<<<<<<<<<<<<<<<<----- esto va al api
    ciphertext_b64u = request_json.get("handshake_b64u") or request_json.get("ciphertext_b64u")
    if not ciphertext_b64u:
        raise ValueError("Falta 'handshake_b64u' (o 'ciphertext_b64u') en el request")

    # 2) Decodificar handshake RSA → datos en claro
    hs = Packet.decrypt_with_rsa(ciphertext_b64u)  # {"username","password","email","aeskey",...}
    aes_key = hs.get("aeskey")
    if not aes_key:
        raise ValueError("El handshake no contiene 'aeskey'")

    username = hs.get("username")
    email    = hs.get("email")
    password = hs.get("password")
    if not username or not email or not password:
        raise ValueError("Faltan campos en el handshake (username, email o password)")
    
    # si esta statefull habilitado le agregamos un user_id random(que no este en la lista de uid) al paket
    # sino lo dejamos en 0 lo que representa que ese feuter esta apagado
    # luego el front lo guarda y lo usa para enviarlo a los endpoints como unica cosa decifrada para que decifre las cosas, si se vencio le aviza 

    # 3) alta usuario en tu store simulado    
    UR.crearUsuario(email,username,password,False) 
    UR.create_user(email,username,password,False)

    # 4) Branch según stateful
    if STATEFULL_ENABLED:
        if DEBUG:
            print("Modo stateful activo: creando sesión en memoria...")
        user_id = str(uuid.uuid4())

        # until = ahora + N minutos (Z en ISO8601)
        until_dt = datetime.now(timezone.utc) + timedelta(minutes=STATEFULL_TOKEN_TIME_MIN)
        until_iso = until_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

        # refresh token según tu implementación
        rt = RefreshToken(user_id).getRefres()

        UR.sesionesRedisStateFull[user_id] = { # en cada mensaje que envian lo mandan sin cifrar, PASARLO A STATICFUNTION
            "aesKey": aes_key,
            "until": until_iso,
            "refreshToken": rt
        }
    else:
        print("Modo stateful deshabilitado: no se crearán sesiones persistentes.")
        user_id = "0"
        rt = None
        until_iso = None

    # 5) armamos acces token para el usuario, siempre se usan accesToken
    AT = AccessToken(sub=username, role="user", jti=str(uuid.uuid4()))

    # planteamos data
    data = {
        "status": "ok",
    }

    # generamos paquete 
    packet = Packet(refresh_token=rt,access_token=AT,data=data,aes_key=aes_key,user_id=user_id)

    # lo encriptamos y formateamos
    encriptedPacket = packet.encriptAES()

    #cargamos la sesion de jwt del refresh
    UR.guardar_sesion_refresh(email=email,refresh_token=rt)

    # retornamos (no esta listo el return, porque no esta cifrando el payload) debemos retornar con la aes
    return encriptedPacket


def login(request_json: Dict[str, Any]) -> Dict[str, str]:
    """
    Request: {"handshake_b64u": "<b64url(RSA-OAEP(JSON))>"}  // alias: "ciphertext_b64u"
    El JSON interno del handshake debe traer: {"username","password","email","aeskey"}.
    Hace lo mismo que register, pero sin crear el usuario:
    - valida credenciales contra la DB (UR.get_user)
    - genera refresh/access token
    - registra la sesión (in-memory por ahora)
    - devuelve Packet cifrado con AES (iv, ciphertext, user_id[, files])
    """
    # 1) Extraer blob RSA del request
    ciphertext_b64u = request_json.get("handshake_b64u") or request_json.get("ciphertext_b64u")
    if not ciphertext_b64u:
        raise ValueError("Falta 'handshake_b64u' (o 'ciphertext_b64u') en el request")

    # 2) Decodificar handshake RSA → datos en claro
    hs = Packet.decrypt_with_rsa(ciphertext_b64u)  # {"username","password","email","aeskey",...}
    aes_key = hs.get("aeskey")
    if not aes_key:
        raise ValueError("El handshake no contiene 'aeskey'")

    username = hs.get("username")
    email    = hs.get("email")
    password = hs.get("password")

    # al menos email o username, y siempre password
    if not password or (not username and not email):
        raise ValueError("Faltan campos en el handshake (email/username o password)")

    # 3) Buscar usuario en DB y validar password
    user = UR.get_user(email=email, username=username, password=password)
    if user is None:
        # credenciales inválidas
        raise ValueError("Credenciales inválidas")

    # 4) Branch según stateful
    if STATEFULL_ENABLED:
        if DEBUG:
            print("Modo stateful activo: creando sesión en memoria (login)...")

        user_id = str(uuid.uuid4())

        # until = ahora + N minutos (Z en ISO8601)
        until_dt = datetime.now(timezone.utc) + timedelta(minutes=STATEFULL_TOKEN_TIME_MIN)
        until_iso = until_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

        # refresh token según tu implementación
        rt = RefreshToken(user_id).getRefres()

        # mantenemos el esquema actual de sesiones in-memory
        UR.sesionesRedisStateFull[user_id] = {
            "aesKey": aes_key,
            "until": until_iso,
            "refreshToken": rt,
        }
    else:
        if DEBUG:
            print("Modo stateful deshabilitado en login: no se crearán sesiones persistentes.")
        user_id = "0"
        rt = None
        until_iso = None  # por ahora no lo usamos

    # 5) Access token para el usuario (como en register)
    # usamos el username del dominio (descargado de DB)
    AT = AccessToken(sub=user.username, role="user", jti=str(uuid.uuid4()))

    # 6) Data de respuesta (podés ir agregando más cosas después)
    data = {
        "status": "ok",
    }

    # 7) Armar y cifrar paquete AES
    packet = Packet(
        refresh_token=rt,
        access_token=AT,
        data=data,
        aes_key=aes_key,
        user_id=user_id,
    )

    encrypted_packet = packet.encriptAES()

    # 8) Guardar sesión de refresh (stateless) usando el email plano del handshake
    # si querés soportar login sólo por username más adelante, habría que
    # reconstruir el email descifrando user.mail con su aesEncriper.
    UR.guardar_sesion_refresh(email=email, refresh_token=rt)

    # 9) Devolver paquete cifrado
    return encrypted_packet

def unlogin(request_json: Dict[str, Any]) -> Dict[str, str]:
    print("un login")

def refresh(request_json: Dict[str, Any]) -> Dict[str, str]: # si ambos metodos estan habilitados va a ver si en el paquete el user_id no sea cero, si es cero le llego un paquete stateless, sino statefull.
    print("refresh acces token")

# funcs para exportar, cuando importen esta libreria, ademas de importar los paths prehechos pueden usar estas funciones para otros endpoint para al inicio y al final del endpoit cifrar o decifrar como deberian hacerlo, bajo el primcipio que haya querido tomar ese endpoint.
# stateLess
def cyphStateLess(request):
    print("cph")
def uncyphStateLess(request):
    print("cph")

# stateFull
def cyphStateFull(request):
    print("cph")
def uncyphStateFull(request):
    print("cph")


# Permite ejecutar directamente desde la consola:
if __name__ == "__main__":
    # cargamos cosas 
    init()
    # instanciamos el Key Management System 
    kms = KMS()
    if DEBUG:
        print("Módulo auth inicializado.\n")


from PaketCipher import rsa_encrypt_b64u_with_public
import json

def test_register_real():
    # === 1) SIMULAR FRONT END ===
    # La aeskey la inventa el front
    aes_key = "0123456789abcdef0123456789abcdef"

    handshake_payload = {
        "username": "mike",
        "password": "contraseña123",
        "email": "mike@example.com",
        "aeskey": aes_key
    }

    # ciframos con RSA pública → base64url
    handshake_b64u = rsa_encrypt_b64u_with_public(handshake_payload)

    # request real de front → backend register()
    request_json = {
        "handshake_b64u": handshake_b64u
    }

    # === 2) EJECUTAR REGISTER ===
    encrypted_packet = register(request_json)

    print("\n=== PACKET CIFRADO QUE DEVUELVE EL REGISTER ===")
    print(json.dumps(encrypted_packet, indent=4))

    # === 3) DESCIFRAR EL PAQUETE ===
    dec = Packet.decryptAES(encrypted_packet, aes_key=aes_key)

    print("\n=== PACKET DESCIFRADO ===")
    print(json.dumps(dec, indent=4))

    refresh_token = dec.get("refresh_token")
    user_id_geted = encrypted_packet.get("user_id")

    print("\n=== USER TESTING ===")
    print("Usuarios logueados: ",UR.sesionesRedisStateFull)
    print("Usuarios RefreshToken: ",UR.sesionesRedisJWT)
    print("Usuarios registrados: ",UR.usuarios)
    print("Check statefull token: ",UR.checkSFToken(refresh_token=refresh_token,id_user=user_id_geted))
    print("Check refresh token: ",UR.checkRefreshToken("mike@example.com",refreshToken=refresh_token))
    print("Testing user get: ",UR.getUser(email="mike@example.com",password="contraseña123",username=None))

    print("Traemos usuario desde la base de datos: ", UR.get_user(username=None,email="mike@example.com",password="contraseña123"))
# Ejecutar test:
#test_register_real()


def test_login_real():
    # === 1) SIMULAR FRONT END ===
    # La aeskey la inventa el front (usamos la misma que en el register)
    aes_key = "0123456789abcdef0123456789abcdef"

    handshake_payload = {
        "username": "mike",
        "password": "contraseña123",
        "email": "mike@example.com",
        "aeskey": aes_key
    }

    # ciframos con RSA pública → base64url
    handshake_b64u = rsa_encrypt_b64u_with_public(handshake_payload)

    # request real de front → backend login()
    request_json = {
        "handshake_b64u": handshake_b64u
    }

    # === 2) EJECUTAR LOGIN ===
    encrypted_packet = login(request_json)

    print("\n=== PACKET CIFRADO QUE DEVUELVE EL LOGIN ===")
    print(json.dumps(encrypted_packet, indent=4))

    # === 3) DESCIFRAR EL PAQUETE ===
    dec = Packet.decryptAES(encrypted_packet, aes_key=aes_key)

    print("\n=== PACKET DESCIFRADO (LOGIN) ===")
    print(json.dumps(dec, indent=4))

    refresh_token = dec.get("refresh_token")
    user_id_geted = encrypted_packet.get("user_id")

    print("\n=== USER TESTING (LOGIN) ===")
    print("Usuarios logueados (stateful): ", UR.sesionesRedisStateFull)
    print("Sesiones RefreshToken (stateless): ", UR.sesionesRedisJWT)
    print("Usuarios registrados en repo:", UR.usuarios)
    print("Check statefull token:", UR.checkSFToken(refresh_token=refresh_token, id_user=user_id_geted))
    print("Check refresh token:", UR.checkRefreshToken("mike@example.com", refreshToken=refresh_token))

test_login_real()