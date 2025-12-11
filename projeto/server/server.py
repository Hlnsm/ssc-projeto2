#!/usr/bin/env python3
import socket
import os
import json
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 5500

OAMS_HOST = '127.0.0.1'
OAMS_PORT = 6001


BLOCKS_DIR = "server/storage/blocks"
META_DIR = "server/storage/metadata"
INDEX_PATH = os.path.join(META_DIR, "index.json")
FILEMAP_PATH = os.path.join(META_DIR, "filemap.json")
META_KEY_PATH = "server/keys/key.txt"

os.makedirs(BLOCKS_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

_meta_key = None
_index_lock = threading.Lock()
_filemap_lock = threading.Lock()

def _load_meta_key() -> bytes:
    global _meta_key
    if _meta_key is None:
        with open(META_KEY_PATH, "r", encoding="utf-8") as f:
            key_hex = f.read().strip()
        try:
            _meta_key = bytes.fromhex(key_hex)
        except ValueError:
            raise ValueError("invalid metadata_key (not hex).")
        if len(_meta_key) not in (16, 24, 32):
            raise ValueError("metadata_key must be 16, 24, or 32 bytes (32 recommended).")
    return _meta_key

def _aesgcm_encrypt_json(obj: dict) -> bytes:
    key = _load_meta_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(obj).encode("utf-8"), None)
    return nonce + ct

def _aesgcm_decrypt_json(blob: bytes) -> dict:
    key = _load_meta_key()
    nonce, ct = blob[:12], blob[12:]
    data = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(data.decode("utf-8"))

def _atomic_write(path: str, data: bytes, mode: str = "wb"):
    tmp = path + ".tmp"
    with open(tmp, mode) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def _load_index_unlocked() -> dict:
    if not os.path.exists(INDEX_PATH):
        return {}
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass
    try:
        with open(INDEX_PATH, "rb") as f:
            blob = f.read()
        return _aesgcm_decrypt_json(blob)
    except Exception:
        pass
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            blob_hex = f.read().strip()
        return _aesgcm_decrypt_json(bytes.fromhex(blob_hex))
    except Exception:
        return {}

def _save_index_unlocked(index: dict) -> None:
    enc = _aesgcm_encrypt_json(index)
    _atomic_write(INDEX_PATH, enc, "wb")

def _load_filemap_unlocked() -> dict:
    if not os.path.exists(FILEMAP_PATH):
        return {}
    try:
        with open(FILEMAP_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass
    try:
        with open(FILEMAP_PATH, "rb") as f:
            blob = f.read()
        return _aesgcm_decrypt_json(blob)
    except Exception:
        pass
    try:
        with open(FILEMAP_PATH, "r", encoding="utf-8") as f:
            blob_hex = f.read().strip()
        return _aesgcm_decrypt_json(bytes.fromhex(blob_hex))
    except Exception:
        return {}

def _save_filemap_unlocked(fm: dict) -> None:
    enc = _aesgcm_encrypt_json(fm)
    _atomic_write(FILEMAP_PATH, enc, "wb")

def load_index() -> dict:
    with _index_lock:
        return _load_index_unlocked()

def save_index(index: dict) -> None:
    with _index_lock:
        _save_index_unlocked(index)

def load_filemap() -> dict:
    with _filemap_lock:
        return _load_filemap_unlocked()

def save_filemap(fm: dict) -> None:
    with _filemap_lock:
        _save_filemap_unlocked(fm)

def update_index(mutator) -> None:
    with _index_lock:
        idx = _load_index_unlocked()
        mutator(idx)
        _save_index_unlocked(idx)

def update_filemap(mutator) -> None:
    with _filemap_lock:
        fm = _load_filemap_unlocked()
        mutator(fm)
        _save_filemap_unlocked(fm)

def oams_check_access(file_id: str, auth_token: str, permission: str) -> bool:
    
    if not auth_token:
       
        print("[OAMS-CHECK] missing auth_token – denying access")
        return False

    req = {
        "op": "CheckAccess",
        "body": {
            "file_id": file_id,
            "permission": permission,
        },
        "sig": None,
        "token": auth_token,
    }

    line = json.dumps(req) + "\n"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((OAMS_HOST, OAMS_PORT))
            s.sendall(line.encode("utf-8"))

            buf = ""
            while "\n" not in buf:
                data = s.recv(4096)
                if not data:
                    break
                buf += data.decode("utf-8", errors="ignore")

        if not buf.strip():
            print("[OAMS-CHECK] empty response")
            return False

        resp_line, _sep, _rest = buf.partition("\n")
        resp_line = resp_line.strip()
        resp = json.loads(resp_line)

        if resp.get("status") != "OK":
            print(f"[OAMS-CHECK] NOK status: {resp.get('error')}")
            return False

        body = resp.get("body", {})
        allowed = bool(body.get("allowed", False))
        print(f"[OAMS-CHECK] file_id={file_id[:16]}... perm={permission} allowed={allowed}")
        return allowed

    except Exception as e:
        print(f"[OAMS-CHECK] error contacting OAMS: {e}")
        return False

def store_block(data):
    block_id = data["block_id"]
    path = os.path.join(BLOCKS_DIR, block_id)
    if os.path.exists(path):
        print(f"[STORE_BLOCK] Dedupe: already exists {block_id}")
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    print(f"[STORE_BLOCK] Stored block: {block_id}")

def store_token(data):
    token = data["token"]
    enc_file_id = data["file_id"]

    def _mut_idx(idx: dict):
        lst = idx.setdefault(token, [])
        if enc_file_id not in lst:
            lst.append(enc_file_id)
    update_index(_mut_idx)

    if "block_ids" in data:
        block_ids = data["block_ids"]
        def _mut_fm(fm: dict):
            fm.setdefault(enc_file_id, block_ids)
        update_filemap(_mut_fm)
        print(f"[STORE_TOKEN] filemap registered for {enc_file_id[:16]}... ({len(block_ids)} blocks)")

    print(f"[STORE_TOKEN] Token {token[:16]}... -> {enc_file_id}")

def search_token(data, conn):
   
    search_token = data.get("search_token") or data.get("token")
    auth_token = data.get("auth_token")  

    if not search_token:
        response = json.dumps([]) + "\n"
        conn.sendall(response.encode())
        print("[SEARCH] missing search_token – returning empty list")
        return

    index = load_index()
    enc_ids = index.get(search_token, [])

    filtered = []
    for enc_id in enc_ids:
        
        if oams_check_access(enc_id, auth_token, "obss:search"):
            filtered.append(enc_id)

    response = json.dumps(filtered) + "\n"
    conn.sendall(response.encode())
    print(f"[SEARCH] Token {search_token[:16]}... -> {len(filtered)} result(s) after OAMS filter")

def get_file(data, conn):
    filename = data.get("filename", "")
    req_ids = data.get("block_ids")
    search_token = data.get("search_token") or data.get("token")
    auth_token   = data.get("auth_token")

    def send_block(block_id: str) -> bool:
        path = os.path.join(BLOCKS_DIR, block_id)
        if not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            block_data = json.load(f)
        conn.sendall((json.dumps(block_data) + "\n").encode())
        return True

   
    if search_token and not req_ids:
        index = load_index()
        fm = load_filemap()
        enc_ids = index.get(search_token, [])

        sent_files = 0
        for enc_id in enc_ids:
            
            if not oams_check_access(enc_id, auth_token, "obss:get"):
                continue

            conn.sendall(
                (json.dumps({"op": "FILE_ID", "file_id": enc_id}) + "\n").encode()
            )
            for bid in fm.get(enc_id, []):
                send_block(bid)
            conn.sendall(b'{"op":"FILE_END"}\n')
            sent_files += 1

        conn.sendall(b'{"op":"GET_END"}\n')
        print(f"[GET token] Sent {sent_files} file(s) for token {search_token[:16]}... (after OAMS filter)")
        return

    
    sent = 0
    if isinstance(req_ids, list) and req_ids:
        for block_id in req_ids:
            if send_block(block_id):
                sent += 1
    else:
        for block_id in os.listdir(BLOCKS_DIR):
            if send_block(block_id):
                sent += 1

    conn.sendall(b'{"op":"GET_END"}\n')
    print(f"[GET] Sent {sent} block(s) for file: {filename}")


def list_blocks(conn):
    files = os.listdir(BLOCKS_DIR)
    response = json.dumps(files) + "\n"
    conn.sendall(response.encode())
    print(f"[LIST_BLOCKS] {len(files)} blocks stored.")

def handle_client(conn, addr):
    print(f"[CONNECTION] Client connected: {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                op = msg.get("op")

                if op == "PUT":
                    conn.sendall(b"ACK\n")
                    print(f"[PUT] Received request for {msg.get('filename','?')}")
                elif op == "STORE_BLOCK":
                    store_block(msg)
                    conn.sendall(b"ACK\n")
                elif op == "STORE_TOKEN":
                    store_token(msg)
                    conn.sendall(b"ACK\n")
                elif op == "SEARCH":
                    search_token(msg, conn)
                elif op == "GET":
                    get_file(msg, conn)
                elif op == "LIST_BLOCKS":
                    list_blocks(conn)
                else:
                    print(f"[WARN] Unknown operation: {op}")
                    conn.sendall(b"ERROR Unknown operation\n")
    finally:
        conn.close()
        print(f"[DISCONNECTED] Client {addr} closed.")

def main():
    try:
        _load_meta_key()
    except Exception as e:
        print(f"[ERROR] Failed to load metadata key: {e}")
        print(
            "Create the key with:\n"
            "  mkdir -p server/keys && python - << 'PY'\n"
            "import os, binascii\n"
            "open('server/keys/key.txt','w').write(binascii.hexlify(os.urandom(32)).decode())\n"
            "PY"
        )
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(128)
        print(f"Server running on {HOST}:{PORT}")
        try:
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Shutting down server...")
        finally:
            print("[OK] Socket closed.")

if __name__ == "__main__":
    main()
