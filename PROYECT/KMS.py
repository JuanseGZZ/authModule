import os
from dotenv import load_dotenv

# --- Carga de entorno ---
load_dotenv()

# --- Singleton base ---
class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


# --- Key Management System ---
class KMS(metaclass=SingletonMeta):
    """Sistema de gestión de claves (KMS)"""
    def __init__(self):
        self.mode = os.getenv("AES_MODE", "gcm")
        self.master_key_path = os.getenv("KMS_MASTER_KEY_PATH", "./keys/kms_master.key")
        self._ensure_master_key()

    def _ensure_master_key(self):
        """Crea la master key si no existe"""
        if not os.path.exists(self.master_key_path):
            os.makedirs(os.path.dirname(self.master_key_path), exist_ok=True)
            with open(self.master_key_path, "wb") as f:
                f.write(os.urandom(32))  # 256 bits
            print(f"🔑 Nueva master key creada en {self.master_key_path}")
        else:
            print(f"🔐 Master key existente: {self.master_key_path}")

    def load_master_key(self) -> bytes:
        """Lee la master key"""
        with open(self.master_key_path, "rb") as f:
            return f.read()


# --- Ejemplo de uso ---
if __name__ == "__main__":
    kms1 = KMS()
    kms2 = KMS()
    print(kms1 is kms2)  # True — singleton
