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

        # refresh token según tu implementación
        rt = RefreshToken(user_id).getRefres()

        UR.guardar_sesion_statefull(user_id=user_id,aes_key=aes_key,refresh_token=rt)
    else:
        print("Modo stateful deshabilitado: no se crearán sesiones persistentes.")
        user_id = "0"
        rt = RefreshToken(user_id).getRefres()
        until_iso = None

    # 5) armamos acces token para el usuario, siempre se usan accesToken
    AT = AccessToken(sub=email, role="user", jti=str(uuid.uuid4()))

    # planteamos data
    data = {
        "status": "ok",
    }

    # generamos paquete 
    packet = Packet(refresh_token=rt,access_token=AT.encode(),data=data,aes_key=aes_key,user_id=user_id)

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

        # refresh token según tu implementación
        rt = RefreshToken(user_id).getRefres()

        # mantenemos el esquema actual de sesiones in-memory
        UR.guardar_sesion_statefull(user_id=user_id,aes_key=aes_key,refresh_token=rt)
    else:
        if DEBUG:
            print("Modo stateful deshabilitado en login: no se crearán sesiones persistentes.")
        user_id = "0"
        rt = RefreshToken(user_id).getRefres()

    # 5) Access token para el usuario (como en register)
    # usamos el username del dominio (descargado de DB)
    AT = AccessToken(sub=user.mail, role="user", jti=str(uuid.uuid4()))

    # 6) Data de respuesta (podés ir agregando más cosas después)
    data = {
        "status": "ok",
    }

    # 7) Armar y cifrar paquete AES
    packet = Packet(
        refresh_token=rt,
        access_token=AT.encode(),
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
    """
    Implementación correcta del protocolo:
    - Si user_id != "0": stateful → la AES está en memoria.
    - Si user_id == "0": stateless → la AES viene cifrada con RSA.
    """

    user_id = request_json.get("user_id")
    if user_id is None:
        return {"status": "error", "msg": "Falta user_id"}

    # ============================================================
    # STATEFUL (user_id != "0")
    # ============================================================
    if user_id != "0":

        ses = UR.get_statefull_session(user_id)
        if not ses:
            return {"status": "error", "msg": "stateful session inexistente"}

        aes_server = ses["aes"]

        # 1) DESCIFRAR TODO EL PAQUETE AES
        try:
            dec = Packet.decryptAES(request_json, aes_key=aes_server)
        except Exception as e:
            return {"status": "error", "msg": f"Error AES decrypt: {str(e)}"}

        # 2) VALIDAR QUE LA AES INTERNA COINCIDA
        aes_interna = dec.get("aes")
        if aes_interna != aes_server:
            return {"status": "error", "msg": "AES interna no coincide. Paquete adulterado"}

        # 3) EXTRAER REFRESH TOKEN
        refresh = dec.get("refresh_token")
        if not refresh:
            return {"status": "error", "msg": "refresh_token faltante"}
        
        # 3.5) VALIDAR refresh contra Redis (stateful)
        if not UR.checkSFToken(refresh_token=refresh, id_user=user_id):
            return {"status": "error", "msg": "refresh_token no valido para esta sesion stateful"}

        # 4) BORRAR SESIONES
        UR.eliminar_sesion_statefull(user_id, aes_server)
        UR.eliminar_sesion_refresh(refresh)

        return {"status": "ok", "msg": "unlogin stateful correcto"}
    # ============================================================
    # STATELESS (user_id == "0")
    # ============================================================
    else:
        aes_field = request_json.get("aes", {})
        if "ciphertext" not in aes_field:
            return {"status": "error", "msg": "Falta campo aes.ciphertext en stateless"}

        # 1) sacar la AES real desencriptando RSA
        try:
            aes_key = Packet.decrypt_with_rsa(aes_field["ciphertext"])
            if not isinstance(aes_key, str):
                return {"status": "error", "msg": "AES decodificada por RSA no es string"}
        except Exception as e:
            return {"status": "error", "msg": f"Error RSA decrypt AES: {str(e)}"}

        # 2) NO le pasamos el campo "aes" a decryptAES,
        #    porque ahí metimos un ciphertext RSA, no AES
        enc_copy = {k: v for k, v in request_json.items() if k != "aes"}

        try:
            dec = Packet.decryptAES(enc_copy, aes_key=aes_key)
        except Exception as e:
            return {"status": "error", "msg": f"Error decryptAES con aes_key: {str(e)}"}

        refresh = dec.get("refresh_token")
        if not refresh:
            return {"status": "error", "msg": "refresh_token faltante"}

        UR.eliminar_sesion_refresh(refresh)

        return {"status": "ok", "msg": "unlogin stateless correcto"}

from typing import Dict, Any
import uuid
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from userRepository import userRepository as UR
from PaketCipher import Packet
from accesToken import AccessToken
from refreshToken import RefreshToken

# si lo tenes en otro lado, deja tu flag
STATEFULL_ENABLED = True

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _wrap_new_aes_under_old(old_aes: str, new_aes: str) -> dict:
    key_bytes = old_aes.encode()[:32].ljust(32, b"0")
    aesgcm = AESGCM(key_bytes)
    iv = secrets.token_bytes(12)
    ct = aesgcm.encrypt(iv, new_aes.encode("utf-8"), None)
    return {"iv": _b64u_enc(iv), "ciphertext": _b64u_enc(ct)}

def refresh(request_json: Dict[str, Any]) -> Dict[str, Any]:
    user_id = request_json.get("user_id")
    if user_id is None:
        return {"status": "error", "msg": "Falta user_id"}

    # ============================================================
    # STATEFUL
    # ============================================================
    if user_id != "0":
        if not STATEFULL_ENABLED:
            return {"status": "error", "msg": "Stateful deshabilitado"}

        ses = UR.get_statefull_session(user_id)
        if not ses:
            return {"status": "error", "msg": "stateful session inexistente"}

        aes_old = ses.get("aes")
        if not isinstance(aes_old, str) or not aes_old:
            return {"status": "error", "msg": "stateful session corrupta (falta aes)"}

        # 1) Descifrar request con AES vieja (la que esta en sf:{user_id})
        try:
            dec = Packet.decryptAES(request_json, aes_key=aes_old)
        except Exception as e:
            return {"status": "error", "msg": f"Error AES decrypt: {str(e)}"}

        # 2) Anti adulteracion: la AES interna debe ser la vieja
        aes_interna = dec.get("aes")
        if aes_interna != aes_old:
            return {"status": "error", "msg": "AES interna no coincide. Paquete adulterado"}

        # 3) Validar refresh viejo contra SF (y TTL)
        old_refresh = dec.get("refresh_token")
        if not old_refresh:
            return {"status": "error", "msg": "refresh_token faltante"}

        if UR.checkSFToken(refresh_token=old_refresh, id_user=user_id) is False:
            return {"status": "error", "msg": "refresh_token no coincide con SF o SF vencida"}

        # 4) Resolver email por refresh (JWT index) y validar refresh en JWT
        # Nota: esto asume que en tu sistema existe el index jwt_rt:{refresh} -> email.
        # Si lo resolves distinto, adapta esta parte.
        from db import redisConecctor as r
        email = r.get(f"jwt_rt:{old_refresh}")
        if not email:
            return {"status": "error", "msg": "No existe sesion JWT asociada a este refresh_token"}

        if not UR.checkRefreshToken(email=email, refreshToken=old_refresh):
            return {"status": "error", "msg": "refresh_token JWT invalido o vencido"}
        
        sub = email
        role = "user"
        if not sub:
            return {"status": "error", "msg": "access_token sin sub"}

        new_at = AccessToken(sub=sub, role=role, jti=str(uuid.uuid4()))
        new_rt = RefreshToken(user_id).getRefres()

        # 6) Rotar AES para stateful
        new_aes = secrets.token_hex(16)

        # 7) Rotar JWT refresh (borrar viejo y guardar nuevo)
        UR.eliminar_sesion_refresh(old_refresh)
        UR.guardar_sesion_refresh(email=email, refresh_token=new_rt)

        # 8) Rotar SF de forma estricta: borrar (validando aes_old) y crear nueva
        # Esto evita SF vieja "pegada" y deja redis consistente.
        UR.eliminar_sesion_statefull(user_id=user_id, aes_key=aes_old)
        UR.guardar_sesion_statefull(user_id=user_id, aes_key=new_aes, refresh_token=new_rt)

        # 9) Responder cifrando TODO con AES vieja (para que el cliente pueda descifrar)
        packet = Packet(
            refresh_token=new_rt,
            access_token=new_at.encode(),
            data={"status": "ok", "mode": "stateful", "aes_rotated": True},
            aes_key=aes_old,
            user_id=user_id,
        )
        out = packet.encriptAES()

        # 10) Transportar AES nueva envuelta bajo AES vieja
        out["aes"] = _wrap_new_aes_under_old(old_aes=aes_old, new_aes=new_aes)
        return out

    # ============================================================
    # STATELESS
    # ============================================================
    else:
        aes_field = request_json.get("aes", {})
        if not isinstance(aes_field, dict) or "ciphertext" not in aes_field:
            return {"status": "error", "msg": "Falta campo aes.ciphertext en stateless"}

        # 1) Descifrar AES real desde RSA
        try:
            hs = Packet.decrypt_with_rsa(aes_field["ciphertext"])
        except Exception as e:
            return {"status": "error", "msg": f"Error RSA decrypt AES: {str(e)}"}

        aes_key = hs.get("aeskey") or hs.get("aes") if isinstance(hs, dict) else hs
        if not isinstance(aes_key, str) or not aes_key:
            return {"status": "error", "msg": "AES decodificada por RSA invalida"}

        # 2) Descifrar payload AES (sin el campo aes que en stateless es RSA)
        enc_copy = {k: v for k, v in request_json.items() if k != "aes"}
        try:
            dec = Packet.decryptAES(enc_copy, aes_key=aes_key)
        except Exception as e:
            return {"status": "error", "msg": f"Error decryptAES con aes_key: {str(e)}"}

        old_refresh = dec.get("refresh_token")
        if not old_refresh:
            return {"status": "error", "msg": "refresh_token faltante"}

        from db import redisConecctor as r
        email = r.get(f"jwt_rt:{old_refresh}")
        if not email:
            return {"status": "error", "msg": "refresh_token desconocido o vencido"}

        if not UR.checkRefreshToken(email=email, refreshToken=old_refresh):
            return {"status": "error", "msg": "refresh_token invalido o vencido"}

        new_at = AccessToken(sub=email, role="user", jti=str(uuid.uuid4()))
        new_rt = RefreshToken("0").getRefres()

        UR.eliminar_sesion_refresh(old_refresh)
        UR.guardar_sesion_refresh(email=email, refresh_token=new_rt)

        # Respuesta stateless: cifrado AES y aes RSA (segun tu protocolo)
        packet = Packet(
            refresh_token=new_rt,
            access_token=new_at.encode(),
            data={"status": "ok", "mode": "stateless"},
            aes_key=aes_key,
            user_id="0",
        )
        out = packet.encriptAES()

        # si queres mantener aes RSA aca, reemplazalo como ya lo haces en tu codigo
        return out



# funcs para exportar, cuando importen esta libreria, ademas de importar los paths prehechos pueden usar estas funciones para otros endpoint para al inicio y al final del endpoit cifrar o decifrar como deberian hacerlo, bajo el primcipio que haya querido tomar ese endpoint.
from typing import Dict, Any
from PaketCipher import Packet, rsa_encrypt_b64u_with_public
from accesToken import AccessToken
from userRepository import userRepository as UR

# ============================================================
# STATELESS
# ============================================================
def uncyphStateLess(request_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entrada (stateless request):
      {
        "user_id": "0",
        "iv": "...",
        "ciphertext": "...",
        "aes": { "iv": "AAAAAAAAAA", "ciphertext": "<RSA(OAEP) b64u>" },
        ["files": ...]
      }

    Salida:
      payload descifrado + "__aes_key" para que el endpoint pueda responder cifrando con la misma AES.
    """
    aes_field = request_json.get("aes", {})
    if not isinstance(aes_field, dict) or "ciphertext" not in aes_field:
        raise ValueError("Falta campo aes.ciphertext en request stateless")

    # 1) RSA -> AES real
    hs = Packet.decrypt_with_rsa(aes_field["ciphertext"])
    if isinstance(hs, dict):
        aes_key = hs.get("aeskey") or hs.get("aes")
    else:
        aes_key = hs

    if not isinstance(aes_key, str) or not aes_key:
        raise ValueError("AES decodificada por RSA invalida")

    # 2) AES decrypt del body (sin aes RSA)
    enc_copy = {k: v for k, v in request_json.items() if k != "aes"}
    dec = Packet.decryptAES(enc_copy, aes_key=aes_key)

    # 3) En stateless, Packet.decryptAES puede devolver dec["aes"] (si venia AES-en-AES)
    # pero en tu protocolo stateless el campo aes NO es AES-en-AES, asi que lo ignoramos.
    dec["__aes_key"] = aes_key
    dec["__mode"] = "stateless"
    return dec


def cyphStateLess(response_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entrada (payload en claro) debe incluir:
      - refresh_token: str
      - access_token: AccessToken o dict(to_json)
      - data: dict
      - files: opcional list[dict]
      - __aes_key: str  (la AES que sacaste de uncyphStateLess)

    Salida:
      paquete cifrado (iv/ciphertext) con AES y aes RSA en el root.
    """
    aes_key = response_json.get("__aes_key")
    if not isinstance(aes_key, str) or not aes_key:
        raise ValueError("Falta __aes_key para cifrar respuesta stateless")

    rt = response_json.get("refresh_token", "")
    at_any = response_json.get("access_token") or {}
    data = response_json.get("data") or {}
    files = response_json.get("files") or []

    pkt = Packet(
        refresh_token=rt,
        access_token=at_any,
        data=data,
        aes_key=aes_key,
        user_id="0",
        files=files,
    )
    out = pkt.encriptAES()

    # En stateless: el campo aes NO va AES-en-AES. Va RSA.
    out["aes"] = {
        "iv": "AAAAAAAAAA",
        "ciphertext": rsa_encrypt_b64u_with_public(aes_key),
    }
    out["user_id"] = "0"
    return out


# ============================================================
# STATEFUL
# ============================================================
def uncyphStateFull(request_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entrada (stateful request):
      {
        "user_id": "<SF user_id>",
        "iv": "...",
        "ciphertext": "...",
        "aes": { "iv": "...", "ciphertext": "..." }  # AES-en-AES (anti-adulteracion)
        ["files": ...]
      }

    Salida:
      payload descifrado + "__aes_key" (AES actual del SF) y "__user_id"
    """
    user_id = request_json.get("user_id")
    if not isinstance(user_id, str) or not user_id or user_id == "0":
        raise ValueError("user_id invalido para stateful")

    ses = UR.get_statefull_session(user_id)
    if not ses:
        raise ValueError("stateful session inexistente")
    aes_sf = ses.get("aes")
    if not isinstance(aes_sf, str) or not aes_sf:
        raise ValueError("stateful session corrupta (falta aes)")

    dec = Packet.decryptAES(request_json, aes_key=aes_sf)

    # anti-adulteracion: la AES interna del paquete debe coincidir con la AES del SF
    aes_interna = dec.get("aes")
    if aes_interna != aes_sf:
        raise ValueError("AES interna no coincide. Paquete adulterado")

    dec["__aes_key"] = aes_sf
    dec["__user_id"] = user_id
    dec["__mode"] = "stateful"
    return dec


def cyphStateFull(response_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entrada (payload en claro) debe incluir:
      - user_id (o __user_id): str
      - refresh_token: str
      - access_token: AccessToken o dict(to_json)
      - data: dict
      - files: opcional list[dict]

    Cifra usando la AES actual del SF en Redis.
    """
    user_id = response_json.get("user_id") or response_json.get("__user_id")
    if not isinstance(user_id, str) or not user_id or user_id == "0":
        raise ValueError("user_id invalido para cifrar stateful")

    ses = UR.get_statefull_session(user_id)
    if not ses:
        raise ValueError("stateful session inexistente")
    aes_sf = ses.get("aes")
    if not isinstance(aes_sf, str) or not aes_sf:
        raise ValueError("stateful session corrupta (falta aes)")

    rt = response_json.get("refresh_token", "")
    at_any = response_json.get("access_token") or {}
    data = response_json.get("data") or {}
    files = response_json.get("files") or []


    pkt = Packet(
        refresh_token=rt,
        access_token=at_any,
        data=data,
        aes_key=aes_sf,
        user_id=user_id,
        files=files,
    )
    out = pkt.encriptAES()
    return out

from typing import Tuple
# check token, verifica si el Acces token es valido
def checkToken(dec: Dict[str, Any]) -> Tuple[bool, Dict[str, Any] | None, str]:
    """
    Valida el Access Token recibido en el paquete ya descifrado.
    Retorna: (ok, payload, error)
    """
    token = dec.get("access_token")

    if not isinstance(token, str) or not token:
        return (False, None, "access_token faltante o invalido")

    ok, payload, err = AccessToken.validate_jwt(token)
    if not ok:
        return (False, None, err)

    return (True, payload, "")
## ejemplo de uso de libreria con esto 
#dec = uncyphStateFull(request_json)  # o uncyphStateLess
#
#ok, payload, err = checkToken(dec)
#if not ok:
#    return {"status": "error", "msg": f"AT invalido: {err}"}
#
## payload ya esta verificado
#user_id = payload["sub"]
#role = payload["role"]

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
#test_login_real()

def test_unlogin_real():
    """
    Flujo:
    - REGISTER usuario mike_unlog
    - LOGIN #1 (stateful) → unlogin() stateful con el paquete tal cual vuelve
    - LOGIN #2 (mismo user) → armamos request stateless y probamos unlogin() stateless
    """
    from sessions import sesionesRedisStateFull as SSF, sesionesRedisJWT as SJWT

    print("\n==============================")
    print("=== TEST UNLOGIN REAL ========")
    print("==============================")

    # limpiar sesiones
    SSF.clear()
    SJWT.clear()

    aes_key = "0123456789abcdef0123456789abcdef"

    # ---------------------------
    # HANDSHAKE COMÚN (REGISTER + LOGIN)
    # ---------------------------
    handshake_payload = {
        "username": "mike_unlog",
        "password": "contraseña123",
        "email": "mike_unlog@example.com",
        "aeskey": aes_key,
    }

    handshake_b64u = rsa_encrypt_b64u_with_public(handshake_payload)
    request_json = {"handshake_b64u": handshake_b64u}

    # ============================
    # LOGIN #1 → STATEFUL
    # ============================
    print("\n[LOGIN #1] Ejecutando login() para stateful...")
    encrypted_packet = login(request_json)
    print("[LOGIN #1] Paquete cifrado:")
    print(json.dumps(encrypted_packet, indent=4))

    user_id = encrypted_packet.get("user_id")
    print(f"[LOGIN #1] user_id: {user_id!r}")
    print("[LOGIN #1] sesionesRedisStateFull:", SSF.sessiones)
    print("[LOGIN #1] sesionesRedisJWT      :", SJWT.sessiones)

    num_str = input("Enter somting to continue")

    # ============================
    # UNLOGIN STATEFUL
    # ============================
    if user_id and user_id != "0":
        print("\n[UNLOGIN STATEFUL] Ejecutando unlogin() con el paquete del login #1...")
        res_sf = unlogin(encrypted_packet)
        print("[UNLOGIN STATEFUL] Resultado:", res_sf)
        print("[UNLOGIN STATEFUL] sesionesRedisStateFull:", SSF.sessiones)
        print("[UNLOGIN STATEFUL] sesionesRedisJWT      :", SJWT.sessiones)

    else:
        print("\n[UNLOGIN STATEFUL] user_id == '0' → no hay stateful para probar.")

    # ============================
    # LOGIN #2 → BASE PARA STATELESS
    # ============================
    print("\n[LOGIN #2] Ejecutando login() de nuevo (mismo usuario)...")
    encrypted_packet2 = login(request_json)
    print("[LOGIN #2] Paquete cifrado:")
    print(json.dumps(encrypted_packet2, indent=4))

    # Desciframos con la AES para ver qué hay adentro y obtener el refresh_token
    dec2 = Packet.decryptAES(encrypted_packet2, aes_key=aes_key)
    print("\n[LOGIN #2] Paquete descifrado con AES:")
    print(json.dumps(dec2, indent=4))

    refresh2 = dec2.get("refresh_token")
    print("[LOGIN #2] refresh_token:", refresh2)
    print("[LOGIN #2] sesionesRedisJWT:", SJWT.sessiones)

    # ============================
    # ARMAR REQUEST STATELESS
    # ============================
    # En stateless:
    # - user_id = "0"
    # - iv y ciphertext son los mismos del paquete AES
    # - aes.ciphertext = AES cifrada con RSA
    # - aes.iv debe existir (aunque no lo usemos), para que decryptAES no rompa
    aes_cipher_rsa = rsa_encrypt_b64u_with_public(aes_key)

    stateless_request = {
        "user_id": "0",
        "iv": encrypted_packet2["iv"],
        "ciphertext": encrypted_packet2["ciphertext"],
        "aes": {
            "iv": "AAAAAAAAAA", # base64url dummy, no se usa en stateless
            "ciphertext": aes_cipher_rsa # AES real cifrada con RSA
        }
        # si quisieras soportar files, copiarías también "files" del encrypted_packet2
    }

    print("\n[UNLOGIN STATELESS] Request armado para unlogin():")
    print(json.dumps(stateless_request, indent=4))

    num_str = input("Enter somting to continue")

    # ============================
    # UNLOGIN STATELESS
    # ============================
    res_sl = unlogin(stateless_request)
    print("\n[UNLOGIN STATELESS] Resultado:", res_sl)
    print("[UNLOGIN STATELESS] sesionesRedisJWT:", SJWT.sessiones)

    print("\n=========== FIN test_unlogin_real ===========\n")
#test_unlogin_real()

def test_refresh_real():
    """
    Flujo (sin REGISTER):
    - LOGIN
    - REFRESH stateful (si aplica) -> rota RT y AES
    - REFRESH stateless -> request nuevo cifrado con AES vigente y aes por RSA
    """
    import json
    from PaketCipher import rsa_encrypt_b64u_with_public

    def step_pause(title: str):
        print("\n--------------------------------------------")
        print(f"[PAUSA] {title}")
        print("ENTER para continuar | 'q' + ENTER para salir")
        x = input("> ").strip().lower()
        if x == "q":
            raise SystemExit("Test abortado por el usuario.")

    def pretty(obj):
        try:
            return json.dumps(obj, indent=4, ensure_ascii=False)
        except Exception:
            return str(obj)

    print("\n==============================")
    print("=== TEST REFRESH REAL (NO REGISTER) ========")
    print("==============================")

    # AES inicial (la que el cliente usa al arrancar en este test)
    client_aes = "0123456789abcdef0123456789abcdef"

    email = "mike_refresh@example.com"
    username = "mike_refresh"
    password = "contraseña123"

    # ---------------------------
    # LOGIN
    # ---------------------------
    step_pause("LOGIN: ejecuta login() y descifra para obtener RT/AT")

    handshake_payload = {
        "username": username,
        "password": password,
        "email": email,
        "aeskey": client_aes,
    }
    handshake_b64u = rsa_encrypt_b64u_with_public(handshake_payload)
    request_json = {"handshake_b64u": handshake_b64u}

    print("\n[LOGIN] Ejecutando login()...")
    login_packet = login(request_json)

    print("[LOGIN] Paquete cifrado (root):")
    print(pretty(login_packet))

    user_id = login_packet.get("user_id")
    print(f"\n[LOGIN] user_id: {user_id!r}")

    dec_login = Packet.decryptAES(login_packet, aes_key=client_aes)
    cur_refresh = dec_login.get("refresh_token")
    cur_access_json = dec_login.get("access_token")

    print("\n[LOGIN] Decifrado (resumen):")
    print("  refresh_token:", cur_refresh)
    print("  access_token payload:", (cur_access_json or {}).get("payload"))
    print("  aes interna:", dec_login.get("aes"))

    assert UR.checkRefreshToken(email=email, refreshToken=cur_refresh) is True, "LOGIN: refresh_token no valido en Redis"

    step_pause("OK: Ahora REFRESH STATEFUL (si aplica)")

    refreshed_packet_stateful = None

    # ===========================
    # REFRESH STATEFUL (si aplica)
    # ===========================
    if user_id and user_id != "0":
        print("\n[REFRESH STATEFUL] Ejecutando refresh() con login_packet...")
        refreshed_packet_stateful = refresh(login_packet)

        print("[REFRESH STATEFUL] Respuesta (root):")
        print(pretty(refreshed_packet_stateful))

        if "iv" not in refreshed_packet_stateful or "ciphertext" not in refreshed_packet_stateful:
            raise RuntimeError(f"[REFRESH STATEFUL] refresh() no devolvio paquete AES. Respuesta: {refreshed_packet_stateful}")

        # Se descifra con AES VIEJA (client_aes)
        dec_ref = Packet.decryptAES(refreshed_packet_stateful, aes_key=client_aes)
        new_refresh = dec_ref.get("refresh_token")
        new_access_json = dec_ref.get("access_token")
        new_aes = dec_ref.get("aes")

        print("\n[REFRESH STATEFUL] Decifrado (resumen):")
        print("  refresh_token nuevo:", new_refresh)
        print("  access_token nuevo payload:", (new_access_json or {}).get("payload"))
        print("  aes nueva (payload):", new_aes)

        step_pause("ASSERTS STATEFUL: RT rota, SF rota, AES rota")

        assert new_refresh and new_refresh != cur_refresh, "STATEFUL: no roto refresh_token"
        assert UR.checkRefreshToken(email=email, refreshToken=new_refresh) is True, "STATEFUL: nuevo refresh no valido (JWT)"
        assert UR.checkRefreshToken(email=email, refreshToken=cur_refresh) is False, "STATEFUL: viejo refresh sigue valido (JWT)"

        assert UR.checkSFToken(refresh_token=new_refresh, id_user=user_id) is True, "STATEFUL: SF no actualizado al nuevo refresh"
        assert UR.checkSFToken(refresh_token=cur_refresh, id_user=user_id) is False, "STATEFUL: SF sigue aceptando refresh viejo"

        assert isinstance(new_aes, str) and new_aes, "STATEFUL: no vino aes nueva en payload"
        assert new_aes != client_aes, "STATEFUL: AES no roto"

        print("\n[STATEFUL] OK. Cliente rota AES.")
        # Cliente rota AES
        client_aes = new_aes
        cur_refresh = new_refresh
        cur_access_json = new_access_json

        step_pause("Seguimos con REFRESH STATELESS (request nuevo cifrado con AES vigente)")

    else:
        print("\n[REFRESH STATEFUL] user_id == '0' (no hay stateful).")
        step_pause("Seguimos con REFRESH STATELESS usando AES actual")

    # ===========================
    # REFRESH STATELESS
    # ===========================
    print("\n[REFRESH STATELESS] Armando request nuevo cifrado con AES vigente...")

    # Construyo un request AES correcto con Packet para garantizar consistencia iv/ciphertext <-> aes_key
    # IMPORTANTE: en stateless, el campo aes del request debe ir RSA, pero el contenido debe estar cifrado con esa misma AES.
    try:
        at_obj = AccessToken.from_json(cur_access_json)
    except Exception as e:
        raise RuntimeError(f"No pude reconstruir AccessToken.from_json(cur_access_json): {e}")

    req_pkt = Packet(
        refresh_token=cur_refresh,
        access_token=at_obj,
        data={"op": "refresh"},
        aes_key=client_aes,
        user_id="0",
    )
    enc_req = req_pkt.encriptAES()

    # Reemplazo aes (AES-en-AES) por aes RSA
    stateless_request = {
        "user_id": "0",
        "iv": enc_req["iv"],
        "ciphertext": enc_req["ciphertext"],
        "aes": {
            "iv": "AAAAAAAAAA",
            "ciphertext": rsa_encrypt_b64u_with_public(client_aes),
        },
    }

    print("[REFRESH STATELESS] Request:")
    print(pretty(stateless_request))

    step_pause("Ejecutamos refresh() stateless ahora.")

    refreshed_sl = refresh(stateless_request)

    print("\n[REFRESH STATELESS] Respuesta (root):")
    print(pretty(refreshed_sl))

    if "iv" not in refreshed_sl or "ciphertext" not in refreshed_sl:
        raise RuntimeError(f"[REFRESH STATELESS] refresh() no devolvio paquete AES. Respuesta: {refreshed_sl}")

    dec_copy = {k: v for k, v in refreshed_sl.items() if k != "aes"}
    dec_ref_sl = Packet.decryptAES(dec_copy, aes_key=client_aes)

    new_refresh_sl = dec_ref_sl.get("refresh_token")
    new_access_sl = dec_ref_sl.get("access_token")

    print("\n[REFRESH STATELESS] Decifrado (resumen):")
    print("  refresh_token nuevo:", new_refresh_sl)
    print("  access_token nuevo payload:", (new_access_sl or {}).get("payload"))

    step_pause("ASSERTS STATELESS: RT rota en JWT (SF no aplica)")

    assert new_refresh_sl and new_refresh_sl != cur_refresh, "STATELESS: no roto refresh_token"
    assert UR.checkRefreshToken(email=email, refreshToken=new_refresh_sl) is True, "STATELESS: nuevo refresh no valido (JWT)"
    assert UR.checkRefreshToken(email=email, refreshToken=cur_refresh) is False, "STATELESS: viejo refresh sigue valido (JWT)"

    print("\n=========== FIN test_refresh_real ===========\n")
#test_refresh_real()


#tests de funciones 
import json
from typing import Any, Dict
from PaketCipher import Packet, rsa_encrypt_b64u_with_public
from accesToken import AccessToken
from userRepository import userRepository as UR
from sessions import sf_delete

def _pretty(x: Any) -> str:
    try:
        return json.dumps(x, indent=4, ensure_ascii=False)
    except Exception:
        return str(x)

def test_crypto_stateless_ops() -> None:
    """
    Simula operatoria stateless:
      FRONT:
        - arma Packet AES con client_aes
        - reemplaza root["aes"] por RSA(client_aes)
      BACK:
        - uncyphStateLess() -> obtiene payload en claro + __aes_key
        - arma respuesta en claro
        - cyphStateLess() -> cifra con __aes_key y pone aes RSA
      FRONT:
        - descifra respuesta con client_aes y valida contenido
    """
    print("\n==============================")
    print("=== TEST CRYPTO STATELESS OPS ===")
    print("==============================")

    # FRONT: clave AES (simulada)
    client_aes = "0123456789abcdef0123456789abcdef"

    at = AccessToken(sub="user_stateless@mail.com", role="user", jti="jti-stateless-1")

    # FRONT: construyo un request AES correcto
    req_pkt = Packet(
        refresh_token="rt_front_1",
        access_token=at.encode(),
        data={"op": "ping", "msg": "hola desde front stateless"},
        aes_key=client_aes,
        user_id="0",
    )
    enc_req = req_pkt.encriptAES()

    # FRONT: en stateless el campo aes del root va por RSA (no AES-en-AES)
    # Importante: en tu codigo actual estas cifrando RSA un JSON string (la AES), no un dict.
    stateless_request = {
        "user_id": "0",
        "iv": enc_req["iv"],
        "ciphertext": enc_req["ciphertext"],
        "aes": {"iv": "AAAAAAAAAA", "ciphertext": rsa_encrypt_b64u_with_public(client_aes)},
    }

    print("\n[FRONT] Request stateless (root):")
    print(_pretty(stateless_request))

    # BACK: descifro entrada
    dec_in = uncyphStateLess(stateless_request)

    print("Chequeo de token AT",checkToken(dec_in))

    print("\n[BACK] uncyphStateLess() -> payload claro:")
    print(_pretty({k: v for k, v in dec_in.items() if not k.startswith("__")}))

    assert dec_in["user_id"] == "0"
    assert dec_in["data"]["op"] == "ping"
    assert dec_in.get("__aes_key") == client_aes

    # BACK: armo respuesta en claro
    resp_plain = {
        "refresh_token": "rt_back_2",
        "access_token": AccessToken(sub="user_stateless@mail.com", role="user", jti="jti-stateless-2").encode(),
        "data": {"ok": True, "echo": dec_in["data"]},
        "files": [],
        "__aes_key": dec_in["__aes_key"],  # necesario para cyphStateLess
    }

    # BACK: cifro salida
    enc_resp = cyphStateLess(resp_plain)
    print("\n[BACK] cyphStateLess() -> respuesta cifrada (root):")
    print(_pretty(enc_resp))

    # FRONT: descifro respuesta con AES conocida (client_aes)
    # En stateless, el root["aes"] es RSA, asi que lo saco antes de decryptAES
    dec_copy = {k: v for k, v in enc_resp.items() if k != "aes"}
    front_dec = Packet.decryptAES(dec_copy, aes_key=client_aes)

    print("Chequeo de token AT",checkToken(front_dec))

    print("\n[FRONT] Respuesta decifrada:")
    print(_pretty(front_dec))

    assert front_dec["data"]["ok"] is True
    assert front_dec["data"]["echo"]["op"] == "ping"

    print("\n[OK] TEST CRYPTO STATELESS OPS PASO\n")
test_crypto_stateless_ops()

def test_crypto_stateful_ops() -> None:
    """
    Simula operatoria stateful:
      PRE:
        - creo SF en Redis (sf:{user_id}) con aes_sf y refresh_sf
      FRONT:
        - arma Packet AES con aes_sf y user_id real (no 0)
      BACK:
        - uncyphStateFull() -> obtiene payload claro + __aes_key (desde redis)
        - arma respuesta
        - cyphStateFull() -> cifra con AES actual del SF
      FRONT:
        - descifra respuesta con aes_sf
    """
    print("\n==============================")
    print("=== TEST CRYPTO STATEFUL OPS ===")
    print("==============================")

    user_id = "sf_user_test_1"
    aes_sf = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # 32 chars
    refresh_sf = "rt_sf_inicial_1"

    # PRE: limpio SF si existia con misma aes
    sf_delete(user_id=user_id, aes=aes_sf)

    # PRE: creo SF en redis
    UR.guardar_sesion_statefull(user_id=user_id, aes_key=aes_sf, refresh_token=refresh_sf)

    # FRONT: request stateful cifrado con aes_sf
    at = AccessToken(sub="user_stateful@mail.com", role="user", jti="jti-sf-1")
    req_pkt = Packet(
        refresh_token=refresh_sf,
        access_token=at.encode(),
        data={"op": "ping", "msg": "hola desde front stateful"},
        aes_key=aes_sf,
        user_id=user_id,
    )
    enc_req = req_pkt.encriptAES()

    print("\n[FRONT] Request stateful (root):")
    print(_pretty(enc_req))

    # BACK: descifro entrada (AES sale de SF redis)
    dec_in = uncyphStateFull(enc_req)
    
    print("Chequeo de token AT",checkToken(dec_in))

    print("\n[BACK] uncyphStateFull() -> payload claro:")
    print(_pretty({k: v for k, v in dec_in.items() if not k.startswith("__")}))

    assert dec_in["user_id"] == user_id
    assert dec_in["data"]["op"] == "ping"
    assert dec_in.get("__aes_key") == aes_sf

    # BACK: armo respuesta en claro (mismo refresh para este test; en tu app real lo rotas en refresh())
    resp_plain = {
        "user_id": user_id,
        "refresh_token": refresh_sf,
        "access_token": AccessToken(sub="user_stateful@mail.com", role="user", jti="jti-sf-2").encode(),
        "data": {"ok": True, "echo": dec_in["data"]},
        "files": [],
    }

    # BACK: cifro salida usando AES de SF (la actual)
    enc_resp = cyphStateFull(resp_plain)
    print("\n[BACK] cyphStateFull() -> respuesta cifrada (root):")
    print(_pretty(enc_resp))

    # FRONT: descifro respuesta con aes_sf
    front_dec = Packet.decryptAES(enc_resp, aes_key=aes_sf)
    print("\n[FRONT] Respuesta decifrada:")
    print(_pretty(front_dec))

    assert front_dec["data"]["ok"] is True
    assert front_dec["data"]["echo"]["op"] == "ping"
    assert front_dec.get("aes") == aes_sf  # Packet incluye aes interna (AES-en-AES) en stateful

    # POST: limpio SF
    sf_delete(user_id=user_id, aes=aes_sf)

    print("\n[OK] TEST CRYPTO STATEFUL OPS PASO\n")
#test_crypto_stateful_ops()