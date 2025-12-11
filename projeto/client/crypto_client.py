# client/crypto_client.py

import os
import base64
import hashlib
import json
import time
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization




def generate_user_keypair():
    
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def export_private_key_pem(priv_key):
    
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def import_private_key_pem(pem_bytes):
   
    return serialization.load_pem_private_key(pem_bytes, password=None)


def export_public_key_raw_b64(pub_key):
    
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode("utf-8")


def import_public_key_raw_b64(pub_b64):
   
    pub_bytes = base64.b64decode(pub_b64)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)



def sha256_bytes(data):
  
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    
    return hashlib.sha256(data).hexdigest()


def generate_salt(num_bytes=16):
    
    return os.urandom(num_bytes)



# Parâmetros de segurança PBKDF2
PBKDF2_ITERATIONS = 100_000  
PBKDF2_HASH_NAME = 'sha256'
PBKDF2_KEY_LENGTH = 32  


def compute_hpw(password, salt, iterations=PBKDF2_ITERATIONS):
  
    if isinstance(password, str):
        pw_bytes = password.encode("utf-8")
    else:
        pw_bytes = password

    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        pw_bytes,
        salt,
        iterations,
        dklen=PBKDF2_KEY_LENGTH
    )


def make_hpw_record(password, iterations=PBKDF2_ITERATIONS):
    
    salt = generate_salt(16)
    hpw_bytes = compute_hpw(password, salt, iterations)

    salt_hex = salt.hex()
    hpw_hex = hpw_bytes.hex()

    
    return f"pbkdf2_sha256${iterations}${salt_hex}${hpw_hex}"


def parse_hpw_record(hpw_record):
   
    parts = hpw_record.split("$")
    
    if len(parts) != 4:
        raise ValueError(f"Invalid hpw_record format: expected 4 parts, got {len(parts)}")
    
    algorithm, iterations_str, salt_hex, hpw_hex = parts
    
    if algorithm != "pbkdf2_sha256":
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    iterations = int(iterations_str)
    salt = bytes.fromhex(salt_hex)
    hpw_bytes = bytes.fromhex(hpw_hex)
    
    return algorithm, iterations, salt, hpw_bytes


def verify_hpw_local(password, hpw_record):
    
    try:
        algorithm, iterations, salt, expected_hpw = parse_hpw_record(hpw_record)
        computed_hpw = compute_hpw(password, salt, iterations)
        
        
        import hmac
        return hmac.compare_digest(computed_hpw, expected_hpw)
    except Exception:
        return False




def generate_nonce(num_bytes=16):
   
    return os.urandom(num_bytes)


def current_timestamp():
    
    return int(time.time())




def sign_bytes(priv_key, data_bytes):
    
    return priv_key.sign(data_bytes)


def sign_bytes_b64(priv_key, data_bytes):
   
    sig = sign_bytes(priv_key, data_bytes)
    return base64.b64encode(sig).decode("utf-8")


def verify_signature(pub_key, data_bytes, sig_bytes):
    
 
    pub_key.verify(sig_bytes, data_bytes)
    return True


def verify_signature_b64(pub_key, data_bytes, sig_b64):
   
    sig_bytes = base64.b64decode(sig_b64)
    return verify_signature(pub_key, data_bytes, sig_bytes)



def import_oas_public_key_raw_b64(pub_b64):
    
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub_bytes = base64.b64decode(pub_b64)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


def canonical_json_bytes(obj):
   
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_oas_response_signature(resp: dict, oas_pub_b64: str) -> bool:
    
    sig_b64 = resp.get("sig")
    if not sig_b64:
        return False

    
    unsigned = dict(resp)
    unsigned.pop("sig", None)

    data = canonical_json_bytes(unsigned)
    sig_bytes = base64.b64decode(sig_b64)

    pub = import_oas_public_key_raw_b64(oas_pub_b64)
    try:
        pub.verify(sig_bytes, data)
        return True
    except Exception:
        return False
    
def b64url_decode(data_str: str) -> bytes:
    
    rem = len(data_str) % 4
    if rem:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def verify_oas_jwt(token: str, oas_pub_b64: str):
    
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token JWT inválido (esperado 3 partes).")

    header_b64, payload_b64, sig_b64 = parts

    
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    
    sig_bytes = b64url_decode(sig_b64)

    
    pub = import_oas_public_key_raw_b64(oas_pub_b64)

    
    pub.verify(sig_bytes, signing_input)

    
    header_json = b64url_decode(header_b64).decode("utf-8")
    payload_json = b64url_decode(payload_b64).decode("utf-8")

    header = json.loads(header_json)
    payload = json.loads(payload_json)

    return header, payload




def sign_body_json_b64(priv_key, body_dict):
    
    data = canonical_json_bytes(body_dict)
    return sign_bytes_b64(priv_key, data)



def build_auth_message(nonce, ts, ctx, hpw_bytes=None):
    
    parts = []
    
    nonce_b64 = base64.b64encode(nonce).decode("utf-8")
    parts.append(nonce_b64)
    parts.append(str(ts))
    parts.append(ctx)

    if hpw_bytes is not None:
        parts.append(hpw_bytes.hex())

    
    m_str = "|".join(parts)
    return m_str.encode("utf-8")