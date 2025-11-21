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
            "sub": sub,                             # usuario/subject
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

    # ---------- validación estricta ----------
    def validate(
        self,
        token: str,
        *,
        check_jti: Optional[str] = None,
        check_role: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Valida:
          - Header.alg (debe coincidir)
          - Firma
          - exp / nbf / iat (con leeway)
          - iss / aud
          - (opcional) jti == check_jti
          - (opcional) role == check_role
        Retorna: (ok, payload|None, error|None)
        """
        try:
            hdr = jwt.get_unverified_header(token)
            if hdr.get("alg") != self.algorithm:
                return (False, None, f"Algoritmo inválido: se esperaba {self.algorithm}")
            if self.kid and hdr.get("kid") != self.kid:
                return (False, None, "KID inválido")

            payload = self.decode(token)

            if check_jti is not None and payload.get("jti") != check_jti:
                return (False, None, "JTI no coincide")
            if check_role is not None and payload.get("role") != check_role:
                return (False, None, "Role no coincide")

            # chequeo extra: iat no demasiado en el futuro
            iat = payload.get("iat")
            if isinstance(iat, (int, float)):
                iat_dt = datetime.datetime.utcfromtimestamp(iat)
            else:
                iat_dt = iat
            if isinstance(iat_dt, datetime.datetime):
                now = datetime.datetime.utcnow()
                if iat_dt - now > datetime.timedelta(seconds=self.leeway):
                    return (False, None, "iat está en el futuro")

            return (True, payload, None)

        except jwt.ExpiredSignatureError:
            return (False, None, "Token expirado")
        except jwt.ImmatureSignatureError:
            return (False, None, "Token aún no válido (nbf)")
        except jwt.InvalidIssuerError:
            return (False, None, "Issuer inválido (iss)")
        except jwt.InvalidAudienceError:
            return (False, None, "Audience inválida (aud)")
        except jwt.InvalidSignatureError:
            return (False, None, "Firma inválida")
        except jwt.MissingRequiredClaimError as e:
            return (False, None, f"Falta claim requerido: {str(e)}")
        except jwt.InvalidTokenError as e:
            return (False, None, f"Token inválido: {str(e)}")
        
    def _ts(self, dt: Any) -> int:
        """Convierte datetime a epoch (int). Si ya es numérico, lo devuelve."""
        if isinstance(dt, datetime.datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return int(dt.timestamp())
        if isinstance(dt, (int, float)):
            return int(dt)
        raise TypeError("Timestamp inválido en payload")

    def to_json(self) -> Dict[str, Any]:
        """
        Serializa el AccessToken para transporte/pruebas (no firma).
        - headers: dict JOSE (typ/alg[/kid])
        - payload: claims con iat/nbf/exp en epoch
        """
        payload = dict(self.payload)
        # normalizamos timestamps
        for k in ("iat", "nbf", "exp"):
            if k in payload:
                payload[k] = self._ts(payload[k])

        headers = dict(self.headers)
        out = {
            "headers": headers,
            "payload": payload,
        }
        # (opcional) incluir alg/kid por claridad externa
        out["algorithm"] = self.algorithm
        if self.kid:
            out["kid"] = self.kid
        return out
    
    @classmethod
    def from_json(cls, data: dict) -> "AccessToken":
        """
        Reconstruye un AccessToken generado por to_json().
        - Usa el ctor (sub, role, jti)
        - Convierte iat/nbf/exp a datetime
        - Reestablece algorithm/kid/headers/payload
        """
        headers = dict(data.get("headers", {}))
        payload = dict(data.get("payload", {}))

        # mínimos requeridos por tu __init__
        sub  = payload.get("sub", "")
        role = payload.get("role", "")
        jti  = payload.get("jti", "")

        at = cls(sub=sub, role=role, jti=jti)

        # algorithm/kid (prioriza dato entrante; fallback al env/actual)
        alg = data.get("algorithm") or headers.get("alg") or at.algorithm
        kid = data.get("kid", headers.get("kid"))

        at.algorithm = alg
        at.kid = kid

        # normalizar timestamps a datetime
        def _to_dt(x):
            if isinstance(x, (int, float)):
                return datetime.datetime.utcfromtimestamp(int(x))
            return x

        for k in ("iat", "nbf", "exp"):
            if k in payload:
                payload[k] = _to_dt(payload[k])

        # reconstruir headers JOSE coherentes
        at.headers = {"typ": "JWT", "alg": at.algorithm}
        if kid:
            at.headers["kid"] = kid

        # fijar payload completo (incluye iss/aud/etc.)
        at.payload = payload
        return at


# ---- demo mínimo (opcional) ----
def testing():
    import uuid
    at = AccessToken(sub="user123", role="admin", jti=str(uuid.uuid4()))
    t = at.encode()
    ok, payload, err = at.validate(t, check_role="admin")
    print("OK" if ok else f"ERR: {err}", payload if ok else "")


#testing()