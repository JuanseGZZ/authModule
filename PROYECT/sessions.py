from datetime import datetime, timezone, timedelta
import os

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

# para los dias del refresh
JWT_REFRESH_TTL_DAYS = int(os.getenv("JWT_REFRESH_TTL_DAYS", "30"))
STATEFULL_TOKEN_TIME_MIN = int(os.getenv("STATEFULL_TOKEN_TIME_MIN", "15"))

class sesionesRedisJWT:
    sessiones = []

    def __init__(self,email:str,refreshtoken:str):
        self.email = email
        self.refreshToken = refreshtoken
        self.until = _now_utc() + timedelta(days=JWT_REFRESH_TTL_DAYS)
        
        # guardamos en cache
        sesionesRedisJWT.sessiones.append(self)

        # meter en db la sesion nueva 
    
    def __repr__(self):
        return f"sesionesRedisJWT(email={self.email}, until={self.until}, refreshToken={self.refreshToken})"
    
    @staticmethod
    def delete(refresh_token: str) -> bool:
        for i, s in enumerate(sesionesRedisJWT.sessiones):
            if s.refreshToken == refresh_token:
                del sesionesRedisJWT.sessiones[i]
                return True
        return False

    @staticmethod
    def refresh_valido(refresh_token: str) -> bool:
        for s in sesionesRedisJWT.sessiones:
            if s.refreshToken == refresh_token:
                return _now_utc() < s.until
        return False

    @staticmethod
    def clear():
        sesionesRedisJWT.sessiones.clear()

    @staticmethod
    def check(email: str, refresh_token: str) -> bool:
        for s in sesionesRedisJWT.sessiones:
            if s.email == email:
                return (s.refreshToken == refresh_token) and (_now_utc() < s.until)
        return False



class sesionesRedisStateFull:
    sessiones = []

    def __init__(self,user_id:str,aesKey:str,refreshToken:str):
        self.user_id = user_id
        self.aesKey = aesKey

        # until = ahora + N minutos (Z en ISO8601)
        until_dt = datetime.now(timezone.utc) + timedelta(minutes=STATEFULL_TOKEN_TIME_MIN)

        self.until = until_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.refreshToken = refreshToken

        # guardamos en cache
        sesionesRedisStateFull.sessiones.append(self)

        # meter en db la sesion nueva

    def __repr__(self):
        return (
            f"sesionesRedisStateFull("
            f"user_id={self.user_id}, "
            f"aesKey={self.aesKey}, "
            f"until={self.until}, "
            f"refreshToken={self.refreshToken}"
            f")"
        )
    
    @staticmethod
    def delete(user_id: str, aes_key: str) -> bool:
        for i, s in enumerate(sesionesRedisStateFull.sessiones):
            if s.user_id == user_id:
                if s.aesKey != aes_key:
                    return False
                del sesionesRedisStateFull.sessiones[i]
                return True
        return False
    
    @staticmethod
    def clear() -> None:
        sesionesRedisStateFull.sessiones.clear()

    @staticmethod
    def get(user_id: str):
        for s in sesionesRedisStateFull.sessiones:
            if s.user_id == user_id:
                return {
                    "aesKey": s.aesKey,
                    "until": s.until,
                    "refreshToken": s.refreshToken,
                }
        return None
    
    @staticmethod
    def check(refresh_token: str, user_id: str) -> bool:
        ses = sesionesRedisStateFull.get(user_id)
        if not ses:
            return False
        if ses.get("refreshToken") != refresh_token:
            return False
        until = ses.get("until")
        if isinstance(until, str):
            try:
                if until.endswith("Z"):
                    until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
                else:
                    until_dt = datetime.fromisoformat(until)
            except ValueError:
                return False
        else:
            until_dt = until
        return _now_utc() < until_dt

