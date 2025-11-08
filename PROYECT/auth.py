# auth.py
import os

# Importamos los módulos base del sistema de autenticación
from ensureKeys import ensure_keys
from PaketCipher import Packet
from accesToken import AccessToken
from refreshToken import RefreshToken
from DBController import DBC
from KMS import KMS

from typing import Dict, Any

from userModels import User

#Lista de usuarios registrados simulada
usuarios: list[User] = []

# Simulación de sesiones JWT (stateless)
sesionesRedisJWT: list[Dict[str, str]] = []  # [{"email": ..., "refreshToken": ...}]

# Simulación de sesiones stateful (sólo si está habilitado)
sesionesRedisStateFull: Dict[str, Dict[str, str]] = {}  # {"user_id": {"aesKey": ..., "until": ...}}

# Cargamos el flag desde .env
STATEFULL_ENABLED = os.getenv("STATEFULL_ENABLED", "false").lower() == "true"

def init() -> None:
    """
    Inicializa el entorno de autenticación:
    - Verifica (o genera) las claves RSA y AES necesarias para el sistema.
    - Carga las variables de entorno (.env).
    - Informa las rutas de las claves creadas o encontradas.
    """
    print("🔑 Iniciando módulo de autenticación...")
    keys = ensure_keys()
    print("✅ Claves verificadas o generadas correctamente.")
    print(f"RSA (enc) privada: {keys.ec_priv}")
    print(f"RSA (enc) pública : {keys.ec_pub}")
    print(f"RSA (sign) priv   : {keys.rsa_priv}")
    print(f"RSA (sign) pub    : {keys.rsa_pub}")
    print(f"AES master key    : {keys.aes_key}")

    print(f"🧠 STATEFULL_ENABLED = {STATEFULL_ENABLED}")
    if STATEFULL_ENABLED:
        global sesionesRedisStateFull
        sesionesRedisStateFull = {}
        print("🧩 Sesiones stateful activadas (Redis simulado en memoria).")
    else:
        print("⚙️ Modo stateful deshabilitado — no se crearán sesiones persistentes.")

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
    if not username:
        raise ValueError("El handshake no contiene 'username'")

    # creamos el usuario

    # si esta statefull habilitado le agregamos un user_id random(que no este en la lista de uid) al paket
    # sino lo dejamos en 0 lo que representa que ese feuter esta apagado
    # luego el front lo guarda y lo usa para enviarlo a los endpoints como unica cosa decifrada para que decifre las cosas, si se vencio le aviza 
    # 


def login(request) -> Packet:
    print("login")

def unlogin(request) -> None:
    print("un login")

def refresh(request) -> Packet:
    print("refresh acces token")

# funcs para exportar 
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
    # conectamos las DB
    dataBaseController = DBC()
    # instanciamos el Key Management System 
    kms = KMS()
    print("Módulo auth inicializado.\n")