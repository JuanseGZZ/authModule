from auth import * 

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
#test_crypto_stateless_ops()

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
test_crypto_stateful_ops()