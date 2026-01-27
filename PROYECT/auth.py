# auth.py
import os
import uuid
import base64
import secrets
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ensureKeys import ensure_keys
from KMS import KMS
from PaketCipher import Packet, rsa_encrypt_b64u_with_public
from userRepository import userRepository as UR
from accesToken import AccessToken
from refreshToken import RefreshToken

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

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _wrap_new_aes_under_old(old_aes: str, new_aes: str) -> dict:
    key_bytes = old_aes.encode()[:32].ljust(32, b"0")
    aesgcm = AESGCM(key_bytes)
    iv = secrets.token_bytes(12)
    ct = aesgcm.encrypt(iv, new_aes.encode("utf-8"), None)
    return {"iv": _b64u_enc(iv), "ciphertext": _b64u_enc(ct)}

def refresh(request_json: Dict[str, Any]) -> Dict[str, Any]:
    from db import redisConecctor as r
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
        print(old_refresh)
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

def checkTokenRol(dec: Dict[str, Any],rol:str):
    print("checkea que el rol sea valido, y ademas que el at este valido")

# Permite ejecutar directamente desde la consola:
if __name__ == "__main__":
    # cargamos cosas 
    init()
    # instanciamos el Key Management System 
    kms = KMS()
    if DEBUG:
        print("Módulo auth inicializado.\n")
