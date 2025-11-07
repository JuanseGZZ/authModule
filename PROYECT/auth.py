# auth.py
import os

# Importamos los módulos base del sistema de autenticación
from ensureKeys import ensure_keys
from PaketCipher import Packet
from accesToken import AccessToken
from refreshToken import RefreshToken
from DBController import DBC

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

    # conectamos las DB
    dataBaseController = DBC()

    #hacer KMS

    print("Módulo auth inicializado.\n")



# Permite ejecutar directamente desde la consola:
if __name__ == "__main__":
    init()
