from datetime import datetime, timezone, timedelta
import os
from db import redisConecctor as r
from time import time
import json

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

# para los dias del refresh
JWT_REFRESH_TTL_DAYS = int(os.getenv("JWT_REFRESH_TTL_DAYS", "30"))
STATEFULL_TOKEN_TIME_MIN = int(os.getenv("STATEFULL_TOKEN_TIME_MIN", "15"))

# querys JWT to Redis
def jwt_set(email: str, refresh: str, ttl_sec: int):
    until = int(time()) + ttl_sec
    r.set(f"jwt:{email}", json.dumps({"refresh": refresh, "until": until}), ex=ttl_sec)
    r.set(f"jwt_rt:{refresh}", email, ex=ttl_sec)

def jwt_check(email: str, refresh: str) -> bool:
    raw = r.get(f"jwt:{email}")
    if not raw:
        return False
    data = json.loads(raw)
    return data["refresh"] == refresh and time() < data["until"]

def jwt_delete_by_refresh(refresh: str) -> bool:
    email = r.get(f"jwt_rt:{refresh}")
    if not email:
        return False
    r.delete(f"jwt:{email}")
    r.delete(f"jwt_rt:{refresh}")
    return True

class sesionesRedisJWT:
    sessiones = []

    def __init__(self,email:str,refreshtoken:str):
        self.email = email
        self.refreshToken = refreshtoken
        self.until = _now_utc() + timedelta(days=JWT_REFRESH_TTL_DAYS)
        
        # meter en db la sesion nueva 
        segundosTTL = JWT_REFRESH_TTL_DAYS*24*60*60
        jwt_set(email=email,refresh=refreshtoken,ttl_sec=segundosTTL)
    
    def __repr__(self):
        return f"sesionesRedisJWT(email={self.email}, until={self.until}, refreshToken={self.refreshToken})"
    
    @staticmethod
    def delete(refresh_token: str) -> bool:
        return jwt_delete_by_refresh(refresh=refresh_token)
        #for i, s in enumerate(sesionesRedisJWT.sessiones):
        #    if s.refreshToken == refresh_token:
        #        del sesionesRedisJWT.sessiones[i]
        #        return True
        #return False

    @staticmethod
    def refresh_valido(refresh_token: str) -> bool:
        print("refresh")
        #for s in sesionesRedisJWT.sessiones:
        #    if s.refreshToken == refresh_token:
        #        return _now_utc() < s.until
        #return False

    @staticmethod
    def clear():
        sesionesRedisJWT.sessiones.clear()

    @staticmethod
    def check(email: str, refresh_token: str) -> bool:
        return jwt_check(email=email,refresh=refresh_token)
        #for s in sesionesRedisJWT.sessiones:
        #    if s.email == email:
        #        return (s.refreshToken == refresh_token) and (_now_utc() < s.until)
        #return False


# querys statefull to redis
def sf_set(user_id: str, aes: str, refresh: str, ttl_sec: int):
    until = int(time()) + ttl_sec
    r.set(
        f"sf:{user_id}",
        json.dumps({"aes": aes, "refresh": refresh, "until": until}),
        ex=ttl_sec
    )

def sf_get(user_id: str):
    raw = r.get(f"sf:{user_id}")
    if not raw:
        return None
    return json.loads(raw)

def sf_check(user_id: str, refresh: str) -> bool:
    ses = sf_get(user_id)
    if not ses:
        return False
    return ses["refresh"] == refresh and time() < ses["until"]

def sf_delete(user_id: str, aes: str) -> bool:
    ses = sf_get(user_id)
    if not ses:
        return False
    if ses["aes"] != aes:
        return False
    r.delete(f"sf:{user_id}")
    return True


class sesionesRedisStateFull:
    sessiones = [] #cache de sesiones

    def __init__(self,user_id:str,aesKey:str,refreshToken:str):
        self.user_id = user_id
        self.aesKey = aesKey

        # until = ahora + N minutos (Z en ISO8601)
        until_dt = datetime.now(timezone.utc) + timedelta(minutes=STATEFULL_TOKEN_TIME_MIN)

        self.until = until_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.refreshToken = refreshToken

        # meter en db la sesion nueva
        sf_set(user_id=user_id,aes=aesKey,refresh=refreshToken,ttl_sec=STATEFULL_TOKEN_TIME_MIN*60)

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
        return sf_delete(user_id=user_id,aes=aes_key)
        #for i, s in enumerate(sesionesRedisStateFull.sessiones):
        #    if s.user_id == user_id:
        #        if s.aesKey != aes_key:
        #            return False
        #        del sesionesRedisStateFull.sessiones[i]
        #        return True
        #return False
    
    @staticmethod
    def clear() -> None:
        sesionesRedisStateFull.sessiones.clear()

    @staticmethod
    def get(user_id: str):
        return sf_get(user_id=user_id)
        #for s in sesionesRedisStateFull.sessiones:
        #    if s.user_id == user_id:
        #        return {
        #            "aesKey": s.aesKey,
        #            "until": s.until,
        #            "refreshToken": s.refreshToken,
        #        }
        #return None
    
    @staticmethod
    def check(refresh_token: str, user_id: str) -> bool:
        return sf_check(user_id=user_id,refresh=refresh_token)
        #ses = sesionesRedisStateFull.get(user_id)
        #if not ses:
        #    return False
        #if ses.get("refreshToken") != refresh_token:
        #    return False
        #until = ses.get("until")
        #if isinstance(until, str):
        #    try:
        #        if until.endswith("Z"):
        #            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
        #        else:
        #            until_dt = datetime.fromisoformat(until)
        #    except ValueError:
        #        return False
        #else:
        #    until_dt = until
        #return _now_utc() < until_dt



def test_sessions_redis():
    print("=== TEST JWT ===")
    email = "test@example.com"
    refresh = "rt_test_123"

    # limpiar si quedo algo viejo
    jwt_delete_by_refresh(refresh)

    print("Creando JWT session...")
    sesionesRedisJWT(email=email, refreshtoken=refresh)

    print("Check correcto:", jwt_check(email=email, refresh=refresh))
    print("Check incorrecto:", jwt_check(email=email, refresh="otro"))

    print("Delete JWT:", jwt_delete_by_refresh(refresh))
    print("Check post delete:", jwt_check(email=email, refresh=refresh))

    print("\n=== TEST STATEFULL ===")
    user_id = "user_123"
    aes = "aes_test_456"
    refresh_sf = "rt_sf_789"

    # limpiar si quedo algo viejo
    sf_delete(user_id=user_id, aes=aes)

    print("Creando SF session...")
    sesionesRedisStateFull(user_id=user_id, aesKey=aes, refreshToken=refresh_sf)

    print("Get SF:", sf_get(user_id))
    print("Check correcto:", sf_check(user_id=user_id, refresh=refresh_sf))
    print("Check incorrecto:", sf_check(user_id=user_id, refresh="otro"))

    print("Delete SF:", sf_delete(user_id=user_id, aes=aes))
    print("Get post delete:", sf_get(user_id))

    print("\n=== FIN TEST ===")

if __name__ == "__main__":
    test_sessions_redis()
