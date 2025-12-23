import os
import jwt
import datetime
from typing import Any, Dict, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

class AccessToken:
    def __init__(self, sub: str, role: str, jti: str) -> None:
        # --- Config base ---
        self.issuer = os.getenv("JWT_ISS") or os.getenv("JWT_ISSUER") or "https://tuapp.com"
        self.audience = os.getenv("JWT_AUD") or os.getenv("JWT_AUDIENCE") or "https://api.tuapp.com"
        self.algorithm = os.getenv("JWT_SIGN_ALG", "RS256")
        self.ttl_min = int(os.getenv("JWT_ACCESS_TTL_MIN", "15"))
        self.leeway = int(os.getenv("JWT_CLOCK_SKEW_SEC", "60"))
        self.kid = os.getenv("JWT_KID", None)

        # --- Claves ---
        priv_path = os.getenv("JWT_PRIVATE_KEY_PATH") or os.getenv("RSA_SIGN_PRIVATE_KEY_PATH")
        pub_path  = os.getenv("JWT_PUBLIC_KEY_PATH")  or os.getenv("RSA_SIGN_PUBLIC_KEY_PATH")
        if not priv_path or not pub_path:
            raise ValueError("Faltan rutas de claves (JWT_*_KEY_PATH o RSA_SIGN_*_KEY_PATH) en .env")

        with open(priv_path, "r") as f:
            self.private_key = f.read()
        with open(pub_path, "r") as f:
            self.public_key = f.read()

        # --- Estado del token (solo datos de acceso) ---
        now = datetime.datetime.utcnow()
        self.payload: Dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,                             # mail/subject
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + datetime.timedelta(minutes=self.ttl_min),
            "jti": jti,
            "role": role,                           # claim de rol (custom permitido)
        }

        # JOSE header (tip/alg/kid)
        self.headers: Dict[str, Any] = {"typ": "JWT", "alg": self.algorithm}
        if self.kid:
            self.headers["kid"] = self.kid

    # ---------- emisión ----------
    def encode(self) -> str:
        """Firma y devuelve el access token."""
        return jwt.encode(self.payload, self.private_key, algorithm=self.algorithm, headers=self.headers)

    # ---------- decodificación base ----------
    def decode(self, token: str) -> Dict[str, Any]:
        """Decodifica con verificación de firma y claims estándar."""
        return jwt.decode(
            token,
            self.public_key,
            algorithms=[self.algorithm],
            audience=self.audience,
            issuer=self.issuer,
            leeway=self.leeway,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "jti"]},
        )
        
    @staticmethod
    def validate_jwt(token: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        if not isinstance(token, str) or not token:
            return (False, None, "token vacio")

        # issuer/audience igual que el resto de tu clase
        iss = os.getenv("JWT_ISS") or os.getenv("JWT_ISSUER") or "https://tuapp.com"
        aud = os.getenv("JWT_AUD") or os.getenv("JWT_AUDIENCE") or "https://api.tuapp.com"
        alg = os.getenv("JWT_SIGN_ALG", "RS256")

        # 1) obtener public key (contenido PEM)
        pub_path = os.getenv("JWT_PUBLIC_KEY_PATH") or os.getenv("RSA_SIGN_PUBLIC_KEY_PATH")
        pub_pem = os.getenv("JWT_PUBLIC_KEY_PEM")  # opcional si queres guardarla directa en env

        public_key = None

        if pub_pem and "BEGIN PUBLIC KEY" in pub_pem:
            public_key = pub_pem
        elif pub_path:
            try:
                with open(pub_path, "r") as f:
                    public_key = f.read()
            except Exception as e:
                return (False, None, f"No pude leer public key en {pub_path}: {e}")
        else:
            return (False, None, "Falta JWT_PUBLIC_KEY_PATH (o RSA_SIGN_PUBLIC_KEY_PATH) en env")

        # 2) validar JWT (firma + claims)
        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[alg],
                audience=aud,
                issuer=iss,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
            )
            return (True, payload, "")
        except Exception as e:
            return (False, None, str(e))

# ---- demo mínimo (opcional) ----
def testing():
    import uuid
    print("\n==============================")
    print("=== TEST ACCESS TOKEN REAL ===")
    print("==============================")

    # 1) Emitir AT
    at = AccessToken(
        sub="user123",
        role="admin",
        jti=str(uuid.uuid4())
    )

    print("\n[EMISION] Payload original (objeto):")
    print(at.payload)

    # 2) Encode -> JWT STRING
    token = at.encode()

    print("\n[EMISION] JWT firmado (string):")
    print(token)

    # 4) Validacion estatica (sin objeto)
    print("\n[BACK] Validando con validate_jwt() (sin objeto)...")
    ok2, payload2, err2 = AccessToken.validate_jwt(token)

    print("\n[BACK] Resultado validate_jwt():")
    print("  ok     :", ok2)
    print("  payload:", payload2)
    print("  error  :", err2)

    print("\n==============================")
    print("=== FIN TEST ACCESS TOKEN ===")
    print("==============================\n")


#testing()