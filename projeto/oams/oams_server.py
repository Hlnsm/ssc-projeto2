import socket
import threading
import time
from typing import Dict

import os
import json
import base64
import uuid
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from common.protocol import make_response


OAMS_HOST = "127.0.0.1"
OAMS_PORT = 6001

# Diretórios / chaves do OAMS
OAMS_KEYS_DIR = os.path.join("oams", "keys")
OAMS_PRIV_KEY_PATH = os.path.join(OAMS_KEYS_DIR, "oams_priv.pem")
OAMS_PUB_KEY_PATH = os.path.join(OAMS_KEYS_DIR, "oams_pub.b64")

# Diretório / ficheiro de dados (SHARES) do OAMS
OAMS_DATA_DIR = os.path.join("oams", "data")
SHARES_DB_PATH = os.path.join(OAMS_DATA_DIR, "shares_db.json")
SHARES_LOCK = threading.RLock()


# Chave pública do OAS 
OAS_PUB_KEY_PATH = os.path.join("oas", "keys", "oas_pub.b64")




SHARES: Dict[str, dict] = {}



def ensure_oams_keys_dir():
    os.makedirs(OAMS_KEYS_DIR, exist_ok=True)


def ensure_oams_data_dir():
    os.makedirs(OAMS_DATA_DIR, exist_ok=True)


def generate_oams_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def export_oams_private_key_pem(priv_key: Ed25519PrivateKey) -> bytes:
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_oams_public_key_raw_b64(pub_key: Ed25519PublicKey) -> str:
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode("utf-8")


def import_oams_private_key_pem(pem_bytes: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)


def load_or_create_oams_keys():
    
    ensure_oams_keys_dir()

    if not (os.path.exists(OAMS_PRIV_KEY_PATH) and os.path.exists(OAMS_PUB_KEY_PATH)):
        priv, pub = generate_oams_keypair()
        priv_pem = export_oams_private_key_pem(priv)
        with open(OAMS_PRIV_KEY_PATH, "wb") as f:
            f.write(priv_pem)

        pub_b64 = export_oams_public_key_raw_b64(pub)
        with open(OAMS_PUB_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(pub_b64)
    else:
        with open(OAMS_PRIV_KEY_PATH, "rb") as f:
            priv_pem = f.read()
        priv = import_oams_private_key_pem(priv_pem)

        with open(OAMS_PUB_KEY_PATH, "r", encoding="utf-8") as f:
            pub_b64 = f.read().strip()
        return priv, pub_b64

    pub_b64 = export_oams_public_key_raw_b64(priv.public_key())
    return priv, pub_b64


OAMS_PRIV_KEY, OAMS_PUB_KEY_B64 = load_or_create_oams_keys()


def sign_oams_msg(obj: dict) -> str:
    
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = OAMS_PRIV_KEY.sign(data)
    return base64.b64encode(signature).decode("utf-8")




def load_oas_pub_key_b64() -> str:
    with open(OAS_PUB_KEY_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


def import_oas_public_key_raw_b64(pub_b64: str) -> Ed25519PublicKey:
    pub_bytes = base64.b64decode(pub_b64)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


OAS_PUB_KEY_B64 = load_oas_pub_key_b64()
OAS_PUB_KEY = import_oas_public_key_raw_b64(OAS_PUB_KEY_B64)




def b64url_decode(data_str: str) -> bytes:
    
    rem = len(data_str) % 4
    if rem:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def verify_oas_jwt(token: str):
    
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token JWT inválido (esperado 3 partes).")

    header_b64, payload_b64, sig_b64 = parts

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_bytes = b64url_decode(sig_b64)

    # Assinatura Ed25519 com chave pública do OAS
    try:
        OAS_PUB_KEY.verify(sig_bytes, signing_input)
    except InvalidSignature:
        raise ValueError("Assinatura do JWT (OAS) inválida.")

    header_json = b64url_decode(header_b64).decode("utf-8")
    payload_json = b64url_decode(payload_b64).decode("utf-8")

    header = json.loads(header_json)
    payload = json.loads(payload_json)

    
    if header.get("alg") != "EdDSA":
        raise ValueError(f"Algoritmo inesperado no header: {header.get('alg')}")

    # Verificar expiração
    now = int(time.time())
    exp = payload.get("exp")
    if exp is not None and now > exp:
        raise ValueError("Token expirado.")

    return header, payload




def canonical_body_bytes(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_client_sig_from_sub(payload: dict, message, sig_b64: str) -> bool:
   
    if not sig_b64:
        return False

    anon_id = payload.get("sub")
    if not anon_id:
        return False

    try:
        pub_bytes = base64.b64decode(anon_id)
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
    except Exception:
        return False


def pk_fingerprint(pk_b64: str) -> str:
   
    return hashlib.sha256(pk_b64.encode("utf-8")).hexdigest()



def load_shares_from_disk():
    global SHARES
    ensure_oams_data_dir()
    if not os.path.exists(SHARES_DB_PATH):
        SHARES = {}
        return

    try:
        with open(SHARES_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            SHARES = data
        else:
            print("[OAMS] Aviso: ficheiro shares_db.json com formato inválido. A iniciar SHARES vazio.")
            SHARES = {}
    except Exception as e:
        print(f"[OAMS] Erro ao carregar SHARES de disco: {e}")
        SHARES = {}


def save_shares_to_disk():
    ensure_oams_data_dir()
    with SHARES_LOCK:
        try:
            with open(SHARES_DB_PATH, "w", encoding="utf-8") as f:
                json.dump(SHARES, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[OAMS] Erro ao guardar SHARES em disco: {e}")


# Carregar no arranque
load_shares_from_disk()



def handle_oams_test(req: dict) -> dict:
   
    op = req.get("op", "OAMSTest")
    body = req.get("body", {})
    sig = req.get("sig")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    
    try:
        header, payload = verify_oas_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    anon_id = payload.get("sub")
    scope = payload.get("scope", "")
    if not anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

   
    if sig and not verify_client_sig_from_sub(payload, body, sig):
        return make_response(op, status="NOK", error="invalid_client_signature")

    
    body_resp = {
        "msg": "OAMS test OK",
        "anon_id": anon_id,
        "scope": scope,
        "claims": payload,
        "echo_body": body,
    }

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_oams_msg(unsigned)
    return resp



def handle_create_sharing_registration(req: dict) -> dict:
   
    op = req.get("op", "CreateSharingRegistration")
    body = req.get("body", {})
    sig = req.get("sig")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    try:
        header, payload = verify_oas_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    owner_anon_id = payload.get("sub")
    if not owner_anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

    scope = payload.get("scope", "")
   
    if "obss:share" not in scope.split():
        return make_response(op, status="NOK", error="insufficient_scope")

    owner_pub_key = body.get("owner_pub_key")
    file_id = body.get("file_id")
    authorized_pub_key = body.get("authorized_pub_key")
    permissions = body.get("permissions")
    extra = body.get("extra") or {}

    if not owner_pub_key or not file_id or not authorized_pub_key or not permissions:
        return make_response(op, status="NOK", error="invalid_request")

    
    if owner_pub_key != owner_anon_id:
        return make_response(op, status="NOK", error="owner_mismatch")

    
    if not verify_client_sig_from_sub(payload, body, sig or ""):
        return make_response(op, status="NOK", error="invalid_client_signature")

    owner_fpr = pk_fingerprint(owner_pub_key)
    auth_fpr = pk_fingerprint(authorized_pub_key)

    share_id = str(uuid.uuid4())
    now = int(time.time())

    record = {
        "share_id": share_id,
        "owner_fpr": owner_fpr,
        "file_id": file_id,
        "authorized_fpr": auth_fpr,
        "permissions": permissions,
        "extra": extra,
        "created_at": now,
        "status": "active",
    }

    with SHARES_LOCK:
        SHARES[share_id] = record
        save_shares_to_disk()

    print(f"[OAMS] Nova partilha: share_id={share_id} file_id={file_id} perms={permissions}")

    body_resp = {
        "share_id": share_id,
        "file_id": file_id,
        "permissions": permissions,
        
        "owner_fpr": owner_fpr,
        "authorized_fpr": auth_fpr,
        "created_at": now,
        "status": "active",
    }

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_oams_msg(unsigned)
    return resp


def handle_delete_sharing_registration(req: dict) -> dict:
    
    op = req.get("op", "DeleteSharingRegistration")
    body = req.get("body", {})
    sig = req.get("sig")
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    try:
        header, payload = verify_oas_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    owner_anon_id = payload.get("sub")
    if not owner_anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

   
    if not verify_client_sig_from_sub(payload, body, sig or ""):
        return make_response(op, status="NOK", error="invalid_client_signature")

    share_id = body.get("share_id")
    if not share_id:
        return make_response(op, status="NOK", error="invalid_request")

    owner_fpr = pk_fingerprint(owner_anon_id)

    with SHARES_LOCK:
        record = SHARES.get(share_id)
        if not record:
            return make_response(op, status="NOK", error="share_not_found")

        if record.get("owner_fpr") != owner_fpr:
            return make_response(op, status="NOK", error="not_share_owner")

        
        record["status"] = "revoked"
        record["revoked_at"] = int(time.time())
        SHARES[share_id] = record
        save_shares_to_disk()

    print(f"[OAMS] Partilha revogada: share_id={share_id}")

    body_resp = {
        "share_id": share_id,
        "status": "revoked",
    }

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_oams_msg(unsigned)
    return resp

def handle_check_access(req: dict) -> dict:
   
    op = req.get("op", "CheckAccess")
    body = req.get("body", {}) or {}
    token = req.get("token")

    if not token:
        return make_response(op, status="NOK", error="missing_token")

    
    try:
        header, payload = verify_oas_jwt(token)
    except Exception as e:
        return make_response(op, status="NOK", error=f"invalid_token: {e}")

    anon_id = payload.get("sub")
    if not anon_id:
        return make_response(op, status="NOK", error="invalid_token_no_sub")

    file_id = body.get("file_id")
    permission = body.get("permission")

    if not file_id or not permission:
        return make_response(op, status="NOK", error="invalid_request")

    caller_fpr = pk_fingerprint(anon_id)

    allowed = False

    with SHARES_LOCK:
        for rec in SHARES.values():
            if rec.get("status") != "active":
                continue
            if rec.get("file_id") != file_id:
                continue

            perms = rec.get("permissions", [])
            if permission not in perms:
                continue

            owner_fpr = rec.get("owner_fpr")
            authorized_fpr = rec.get("authorized_fpr")

            if caller_fpr == owner_fpr or caller_fpr == authorized_fpr:
                allowed = True
                break

    body_resp = {
        "file_id": file_id,
        "permission": permission,
        "allowed": allowed,
    }

    resp = make_response(op, status="OK", body=body_resp)
    unsigned = dict(resp)
    unsigned.pop("sig", None)
    resp["sig"] = sign_oams_msg(unsigned)
    return resp


OP_HANDLERS = {
    "OAMSTest": handle_oams_test,
    "CreateSharingRegistration": handle_create_sharing_registration,
    "DeleteSharingRegistration": handle_delete_sharing_registration,
    "CheckAccess": handle_check_access,
}




def handle_client(conn: socket.socket, addr):
    print(f"[OAMS] Connection from {addr}")
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
                    print("[OAMS] Ignoring invalid JSON line")
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
        print(f"[OAMS] Error with {addr}: {e}")
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((OAMS_HOST, OAMS_PORT))
        s.listen(5)
        print(f"[OAMS] Listening on {OAMS_HOST}:{OAMS_PORT}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
