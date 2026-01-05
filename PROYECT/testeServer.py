import json
import secrets
import requests

from PaketCipher import Packet, rsa_encrypt_b64u_with_public

BASE = "http://127.0.0.1:8081/v1/auth"


def jprint(title, obj):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def post(url: str, payload: dict) -> dict:
    r = requests.post(url, json=payload, timeout=20)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} {url}\n{r.text}")
    return r.json()


def make_handshake(username: str, email: str, password: str, aeskey: str) -> str:
    hs = {"username": username, "email": email, "password": password, "aeskey": aeskey}
    return rsa_encrypt_b64u_with_public(hs)


def build_stateless_request_packet(aeskey: str, clear_data: dict) -> dict:
    """
    Paquete stateless compatible con uncyphStateLess:
      - iv/ciphertext: AES(data)
      - user_id: "0"
      - aes: RSA(aeskey)
    """
    pkt = Packet(
        refresh_token=clear_data.get("refresh_token", ""),
        access_token=clear_data.get("access_token", ""),
        data=clear_data.get("data", {}),
        aes_key=aeskey,
        user_id="0",
        files=clear_data.get("files", []),
    )

    enc = pkt.encriptAES()
    enc["user_id"] = "0"
    enc["aes"] = {"iv": "AAAAAAAAAA", "ciphertext": rsa_encrypt_b64u_with_public(aeskey)}
    return enc


def main():
    # usuario de prueba
    rnd = secrets.token_hex(4)
    username = f"u_{rnd}"
    email = f"{username}@test.local"
    password = "test1234"
    aeskey = secrets.token_hex(16)  # 32 hex chars

    # 1) REGISTER
    print("[1] REGISTER")
    reg_hs = make_handshake(username, email, password, aeskey)
    try:
        reg = post(f"{BASE}/register", {"handshake_b64u": reg_hs})
        jprint("REGISTER RESPONSE", reg)
    except Exception as e:
        # si ya existiera o falla por otra razon, no corta el test
        print(f"[REGISTER] aviso: {e}")

    # 2) LOGIN
    print("\n[2] LOGIN")
    login_hs = make_handshake(username, email, password, aeskey)
    login = post(f"{BASE}/login", {"handshake_b64u": login_hs})
    jprint("LOGIN RESPONSE", login)

    # 3) PIPELINE STATELESS
    print("\n[3] PIPELINE STATELESS (send paquete cifrado)")
    clear_req = {
        "refresh_token": "",
        "access_token": "",
        "data": {"hello": "world", "from": "client"},
        "files": [],
    }
    stateless_packet = build_stateless_request_packet(aeskey=aeskey, clear_data=clear_req)
    jprint("STATELESS PACKET SENT", stateless_packet)

    out_stateless = post(f"{BASE}/_test/pipeline/stateless", stateless_packet)
    jprint("PIPELINE STATELESS RESPONSE (CIFRADO)", out_stateless)

    # 4) PIPELINE STATEFUL
    print("\n[4] PIPELINE STATEFUL")
    user_id = login.get("user_id")
    if not user_id or user_id == "0":
        print("Stateful no activo (user_id=0). Listo.")
        return

    # FIX: incluir "aes" para que pase el check anti-adulteracion
    stateful_packet = {
        "user_id": user_id,
        "iv": login.get("iv"),
        "ciphertext": login.get("ciphertext"),
        "aes": login.get("aes"),
    }

    # validacion minima para que si falta algo lo veas claro
    if not stateful_packet["iv"] or not stateful_packet["ciphertext"] or not stateful_packet["aes"]:
        raise RuntimeError("LOGIN no devolvio iv/ciphertext/aes completo para probar stateful")

    jprint("STATEFUL PACKET SENT", stateful_packet)

    out_stateful = post(f"{BASE}/_test/pipeline/stateful", stateful_packet)
    jprint("PIPELINE STATEFUL RESPONSE (CIFRADO)", out_stateful)


if __name__ == "__main__":
    main()
