import os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_key(path: str) -> bytes:
    """Lê uma chave em hex a partir de ficheiro."""
    with open(path, "r") as f:
        return bytes.fromhex(f.read().strip())

def encrypt_block(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Cifra um bloco com AES-GCM e devolve (nonce, ciphertext, tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]

def decrypt_block(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)

def name_from_ciphertext(ciphertext: bytes) -> str:
    return hashlib.sha256(ciphertext).hexdigest()

def token_from_keyword(mac_key: bytes, keyword: str) -> str:
    token = hmac.new(mac_key, keyword.encode(), hashlib.sha256).digest()
    return token.hex()
