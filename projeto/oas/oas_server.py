
# oas/oas_server.py
import socket
import threading
import time
import uuid
from typing import Dict

import base64
import hashlib
import hmac
import os
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from common.protocol import make_response


OAS_HOST = "127.0.0.1"
OAS_PORT = 6000

# Diretórios/ficheiros de chaves do OAS
OAS_KEYS_DIR = os.path.join("oas", "keys")
OAS_PRIV_KEY_PATH = os.path.join(OAS_KEYS_DIR, "oas_priv.pem")
OAS_PUB_KEY_PATH = os.path.join(OAS_KEYS_DIR, "oas_pub.b64")


# Parâmetros de hashing no servidor
PBKDF2_ITERATIONS = 200_000
OAS_PEPPER = b"XxjNCg4UJ8oTiN3B54lM5mwLvt4L6nKkQSVeE6oFQF0="  


OAS_DATA_DIR = os.path.join("oas", "data")
USERS_DB_PATH = os.path.join(OAS_DATA_DIR, "users_db.json")

USERS_LOCK = threading.Lock()  # 


def ensure_oas_data_dir():
    os.makedirs(OAS_DATA_DIR, exist_ok=True)


def load_users_from_disk():
    
    ensure_oas_data_dir()
    global USERS

    if not os.path.exists(USERS_DB_PATH):
        USERS = {}
        return

    try:
        with open(USERS_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if isinstance(data, dict):
            USERS = data
        else:
            print("[OAS] Aviso: ficheiro users_db.json corrompido ou no formato errado. A iniciar USERS vazio.")
            USERS = {}
    except Exception as e:
        print(f"[OAS] Erro ao carregar USERS de disco: {e}")
        USERS = {}


def save_users_to_disk():
   
    ensure_oas_data_dir()
    with USERS_LOCK:
        try:
            with open(USERS_DB_PATH, "w", encoding="utf-8") as f:
                json.dump(USERS, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[OAS] Erro ao guardar USERS em disco: {e}")



USERS: Dict[str, dict] = {}


CHALLENGES: Dict[str, dict] = {}


load_users_from_disk()



def b64url_encode(data: bytes) -> str:
    
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_b64url(obj: dict) -> str:
    
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64url_encode(data)

def b64url_decode(data_str: str) -> bytes:
   
    rem = len(data_str) % 4
    if rem:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def ensure_oas_keys_dir():
    os.makedirs(OAS_KEYS_DIR, exist_ok=True)


def generate_oas_keypair():
    
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def export_oas_private_key_pem(priv_key: Ed25519PrivateKey) -> bytes:
   
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_oas_public_key_raw_b64(pub_key: Ed25519PublicKey) -> str:
    
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode("utf-8")


def import_oas_private_key_pem(pem_bytes: bytes) -> Ed25519PrivateKey:
   
    return serialization.load_pem_private_key(pem_bytes, password=None)


def load_or_create_oas_keys():
    
    ensure_oas_keys_dir()

    if not (os.path.exists(OAS_PRIV_KEY_PATH) and os.path.exists(OAS_PUB_KEY_PATH)):
       
        priv, pub = generate_oas_keypair()

        priv_pem = export_oas_private_key_pem(priv)
        with open(OAS_PRIV_KEY_PATH, "wb") as f:
            f.write(priv_pem)

        pub_b64 = export_oas_public_key_raw_b64(pub)
        with open(OAS_PUB_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(pub_b64)
    else:
        
        with open(OAS_PRIV_KEY_PATH, "rb") as f:
            priv_pem = f.read()
        priv = import_oas_private_key_pem(priv_pem)

        
        with open(OAS_PUB_KEY_PATH, "r", encoding="utf-8") as f:
            pub_b64 = f.read().strip()
        return priv, pub_b64

    
    pub_b64 = export_oas_public_key_raw_b64(priv.public_key())
    return priv, pub_b64



OAS_PRIV_KEY, OAS_PUB_KEY_B64 = load_or_create_oas_keys()


def canonical_body_bytes(body: dict) -> bytes:
   
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_client_sig(pub_key_b64: str, message, sig_b64: str) -> bool:
    
    if not sig_b64:
        return False

    try:
        pub_bytes = base64.b64decode(pub_key_b64)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)

        if isinstance(message, dict):
            data = canonical_body_bytes(message)
        elif isinstance(message, bytes):
            data = message
        else:
            data = str(message).encode("utf-8")

        sig = base64.b64decode(sig_b64)
        pub.verify(sig, data)
        return True
    except (ValueError, InvalidSignature):
        return False


def hash_password_server(pwd_hash_client: str) -> str:
   
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        pwd_hash_client.encode("utf-8"),
        salt + OAS_PEPPER,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password_server(stored_hash: str, pwd_hash_client: str) -> bool:
   
    try:
        algorithm, iters_str, salt_hex, hash_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False

        iters = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            pwd_hash_client.encode("utf-8"),
            salt + OAS_PEPPER,
            iters,
        )
        
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def sign_server_msg(obj: dict) -> str:
    
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = OAS_PRIV_KEY.sign(data)
    return base64.b64encode(signature).decode("utf-8")



def issue_token(anon_id: str, nonce: str, scope: str = "obss:read obss:share") -> str:
   

    now = int(time.time())

    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": "oas-key-1",   
    }

    payload = {
       
        "iss": "https://oas.example.com",  
        "sub": anon_id,                    
        "iat": now,
        "exp": now + 120,                  
        
        "nonce": nonce,                    
        "jti": str(uuid.uuid4()),         
        "scope": scope,                   
    }

    header_b64 = json_b64url(header)
    payload_b64 = json_b64url(payload)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    
    signature = OAS_PRIV_KEY.sign(signing_input)
    sig_b64 = b64url_encode(signature)

    jwt = f"{header_b64}.{payload_b64}.{sig_b64}"
    return jwt



def verify_own_jwt(token: str) -> dict:
   
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token JWT inválido (esperado 3 partes).")

    header_b64, payload_b64, sig_b64 = parts

    
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_bytes = b64url_decode(sig_b64)

   
    pub = OAS_PRIV_KEY.public_key()
    pub.verify(sig_bytes, signing_input)

    
    payload_json = b64url_decode(payload_b64).decode("utf-8")
    payload = json.loads(payload_json)

    
    now = int(time.time())
    exp = payload.get("exp")
    if exp is not None and now > exp:
        raise ValueError("Token expirado")

    return payload


# Handlers de operações 

def handle_create_registration(req: dict) -> dict:
    op = req.get("op", "CreateRegistration")
    body = req.get("body", {})
    sig = req.get("sig")

    pub_key = body.get("pub_key")
    pwd_hash_client = body.get("pwd_hash")  
    attrs = body.get("attrs", {})

    if not pub_key or not pwd_hash_client:
        return make_response(
            op,
            status="NOK",
            body={"anon_id": None},
            error="invalid_request",
        )

    
    if not verify_client_sig(pub_key, body, sig or ""):
        return make_response(
            op,
            status="NOK",
            body={"anon_id": None},
            error="invalid_signature",
        )

    
    anon_id = pub_key

    
    stored_pwd_hash = hash_password_server(pwd_hash_client)

    
    USERS[anon_id] = {
        "anon_id": anon_id,
        "pub_key": pub_key,
        "pwd_hash": stored_pwd_hash,
        "attrs": attrs,
        "created_at": int(time.time()),
        "status": "active",
    }
    save_users_to_disk()

    print("[OAS] Novo utilizador registado:")
    print("      anon_id (pk_U):", anon_id)
    print("      attrs:", attrs)

    body_resp = {"anon_id": anon_id}
    resp = make_response(op, status="OK", body=body_resp, error=None)

    
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp

def handle_get_my_registration(req: dict) -> dict:
    op = req.get("op", "GetMyRegistration")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    try:
        payload = verify_own_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    anon_id = payload.get("sub")
    if not anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

    user = USERS.get(anon_id)
    if not user or user.get("status") != "active":
        return make_response(op, status="NOK", error="user_not_found_or_deleted")

   
    body_resp = {
        "anon_id": user["anon_id"],
        "pub_key": user["pub_key"],
        "attrs": user.get("attrs", {}),
        "created_at": user.get("created_at"),
        "status": user.get("status"),
    }

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp



def handle_modify_registration(req: dict) -> dict:
    op = req.get("op", "ModifyRegistration")
    body = req.get("body", {})
    sig = req.get("sig")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    
    try:
        payload = verify_own_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    anon_id = payload.get("sub")
    if not anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

    user = USERS.get(anon_id)
    if not user or user.get("status") != "active":
        return make_response(op, status="NOK", error="user_not_found_or_deleted")

    
    pub_key_b64 = user["pub_key"]
    if sig and not verify_client_sig(pub_key_b64, body, sig):
        return make_response(op, status="NOK", error="invalid_signature")

    
    new_attrs = body.get("new_attrs") or {}
    new_pwd_hpw = body.get("new_pwd_hpw")  
    if not new_attrs and not new_pwd_hpw:
        return make_response(op, status="NOK", error="nothing_to_update")

    
    if new_attrs:
        user["attrs"].update(new_attrs)

    
    if new_pwd_hpw:
        user["pwd_hash"] = hash_password_server(new_pwd_hpw)

    save_users_to_disk()
    
    body_resp = {
        "anon_id": anon_id,
        "attrs": user["attrs"],
    }

    

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp




def handle_delete_registration(req: dict) -> dict:
    op = req.get("op", "DeleteRegistration")
    body = req.get("body", {})  
    sig = req.get("sig")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    
    try:
        payload = verify_own_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    anon_id = payload.get("sub")
    if not anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

    user = USERS.get(anon_id)
    if not user:
        return make_response(op, status="NOK", error="user_not_found")

    
    confirm = body.get("confirm", False)
    if not confirm:
        return make_response(op, status="NOK", error="confirmation_required")

    
    pub_key_b64 = user["pub_key"]
    if sig and not verify_client_sig(pub_key_b64, body, sig):
        return make_response(op, status="NOK", error="invalid_signature")

    
    user["pwd_hash"] = None
    user["attrs"] = {}
    user["status"] = "deleted"

    save_users_to_disk()


    body_resp = {"anon_id": anon_id, "status": "deleted"}
    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp


def handle_auth_start(req: dict) -> dict:
    op = req.get("op", "AuthStart")
    body = req.get("body", {})
    sig = req.get("sig")

    pub_key = body.get("pub_key")
    ctx = body.get("ctx", "default")

    if not pub_key:
        return make_response(op, status="NOK", error="invalid_request")

    
    if not verify_client_sig(pub_key, body, sig or ""):
        return make_response(op, status="NOK", error="invalid_signature")

    anon_id = pub_key
    user = USERS.get(anon_id)
    if not user or user.get("status") != "active":
        
        return make_response(op, status="NOK", error="auth_failed")

    challenge_id = str(uuid.uuid4())
    
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")
    now = int(time.time())

    CHALLENGES[challenge_id] = {
        "anon_id": anon_id,
        "pub_key": pub_key,
        "nonce_b64": nonce_b64,
        "ts": now,
        "ctx": ctx,
        "expires_at": now + 60,
    }

    body_resp = {
        "challenge_id": challenge_id,
        "nonce": nonce_b64,
        "ts": now,
        "ctx": ctx,
    }

    resp = make_response("AuthChallenge", status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp
   


def build_auth_message_server(nonce_b64, ts, ctx, hpw_hex=None):
    
    parts = [nonce_b64, str(ts), ctx]
    if hpw_hex is not None:
        parts.append(hpw_hex)
    m_str = "|".join(parts)
    return m_str.encode("utf-8")

def handle_auth_response(req: dict) -> dict:
    op = req.get("op", "AuthResponse")
    body = req.get("body", {})
    sig = req.get("sig")

    pub_key = body.get("pub_key")
    challenge_id = body.get("challenge_id")
    sig_m_b64 = body.get("sig_m")
    pw_proof = body.get("pw_proof")  

    
    if not pub_key or not challenge_id or not sig_m_b64 or pw_proof is None:
        return make_response(op, status="NOK", error="invalid_request")

    
    if not verify_client_sig(pub_key, body, sig or ""):
        return make_response(op, status="NOK", error="invalid_signature")

    
    challenge = CHALLENGES.pop(challenge_id, None)   
    if not challenge:
        return make_response("AuthResult", status="NOK", error="auth_failed")

    if int(time.time()) > challenge["expires_at"]:
        return make_response("AuthResult", status="NOK", error="auth_failed")

    anon_id = challenge["anon_id"]
    user = USERS.get(anon_id)
    if not user or user.get("status") != "active":
        return make_response("AuthResult", status="NOK", error="auth_failed")

    
    nonce_b64 = challenge["nonce_b64"]
    ts = challenge["ts"]
    ctx = challenge["ctx"]

    m_bytes = build_auth_message_server(nonce_b64, ts, ctx, pw_proof)

    
    try:
        pub_bytes = base64.b64decode(pub_key)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_m_bytes = base64.b64decode(sig_m_b64)
        pub.verify(sig_m_bytes, m_bytes)
    except (ValueError, InvalidSignature):
        return make_response("AuthResult", status="NOK", error="auth_failed")

    
    stored_hash = user.get("pwd_hash")
    if not stored_hash or not verify_password_server(stored_hash, pw_proof):
        return make_response("AuthResult", status="NOK", error="auth_failed")

    
    token = issue_token(anon_id, nonce_b64)

    body_resp = {
        "token": token,
        
        "expires_at": int(time.time()) + 120,
    }

    resp = make_response("AuthResult", status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_server_msg(unsigned)
    return resp


OP_HANDLERS = {
    "CreateRegistration": handle_create_registration,
    "ModifyRegistration": handle_modify_registration,
    "DeleteRegistration": handle_delete_registration,
    "AuthStart": handle_auth_start,
    "AuthResponse": handle_auth_response,
    "GetMyRegistration": handle_get_my_registration,
}



def handle_client(conn: socket.socket, addr):
    print(f"[OAS] Connection from {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data.decode("utf-8", errors="ignore")

           
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    print("[OAS] Ignoring invalid JSON line")
                    continue

                op = req.get("op")
                handler = OP_HANDLERS.get(op)

                if not handler:
                    resp = make_response(op or "UNKNOWN", status="NOK", error="unknown_op")
                else:
                    resp = handler(req)

                
                resp_line = json.dumps(resp) + "\n"
                conn.sendall(resp_line.encode("utf-8"))
    except Exception as e:
        print(f"[OAS] Error with {addr}: {e}")
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((OAS_HOST, OAS_PORT))
        s.listen(5)
        print(f"[OAS] Listening on {OAS_HOST}:{OAS_PORT}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
