#!/usr/bin/env python3
import socket
import os
import json
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5500



def load_crypto_config():
    config = {}
    with open("cryptoconfig.txt", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line or ("=" not in line and ":" not in line):
                continue
            sep = "=" if "=" in line else ":"
            k, v = [t.strip() for t in line.split(sep, 1)]
            digits = "".join(ch for ch in v if ch.isdigit())
            config[k.upper()] = v
            if digits:
                config[k.upper() + "_INT"] = int(digits)
    return config

crypto_cfg = load_crypto_config()
DEDUP_ON = str(crypto_cfg.get("DEDUP", "ON")).strip().upper() in ("ON","1","TRUE","YES")

BLOCK_SIZE = crypto_cfg.get("BLOCKSIZE_INT", 1024)
KEYSIZE_BYTES = (crypto_cfg.get("KEYSIZE_INT", 256)) // 8


def load_key(path):
    with open(path, "r") as f:
        return bytes.fromhex(f.read().strip())


MASTER_KEY = load_key("keys/enc_key.txt")
SEARCH_KEY = load_key("keys/mac_key.txt")
NAME_KEY = SEARCH_KEY  


def assert_len(name, key: bytes, expected: int):
    if len(key) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(key)}.")

assert_len("MASTER_KEY", MASTER_KEY, KEYSIZE_BYTES)
assert_len("SEARCH_KEY", SEARCH_KEY, 32)


INDEX_PATH = "index/client_index.ser"

def load_index():
    if os.path.exists(INDEX_PATH):
        with open(INDEX_PATH, "r") as f:
            return json.load(f)
    return {}

def save_index(index):
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    with open(INDEX_PATH, "w") as f:
        json.dump(index, f, indent=2)


def encrypt_block(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
 
    if DEDUP_ON:
        
        nonce = hashlib.sha256(plaintext).digest()[:12]
    else:
        nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext_with_tag[-16:]
    ciphertext_body = ciphertext_with_tag[:-16]
    return nonce, ciphertext_body, tag


def decrypt_block(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)

def name_from_ciphertext(ciphertext: bytes) -> str:
    return hashlib.sha256(ciphertext).hexdigest()

def token_from_keyword(key: bytes, keyword: str) -> str:
    return hmac.new(key, keyword.encode(), hashlib.sha256).hexdigest()

def encrypt_file_id(file_id: str) -> str:
    aesgcm = AESGCM(SEARCH_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, file_id.encode(), None)
    return (nonce + ct).hex()

def decrypt_file_id(enc_hex: str) -> str:
    data = bytes.fromhex(enc_hex)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(SEARCH_KEY)
    return aesgcm.decrypt(nonce, ct, None).decode()


def send_json(sock, message: dict):
    data = json.dumps(message) + "\n"
    sock.sendall(data.encode())

def recv_ack(sock):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(16)
        if not chunk:
            break
        buf += chunk
    if buf.strip() != b"ACK":
        print(f"[WARN] Unexpected ACK: {buf!r}")

def store_block_rpc(sock, block_name: str, nonce: bytes, ciphertext: bytes, tag: bytes):
    payload = {
        "op": "STORE_BLOCK",
        "block_id": block_name,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }
    send_json(sock, payload)
    recv_ack(sock)


def put_file(sock):
    filepath = input("Enter path of file to upload: ")
    if not os.path.exists(filepath):
        print("File does not exist.")
        return

    filename = os.path.basename(filepath)
    keywords = input("Enter keywords for search (space separated): ").split()

    send_json(sock, {"op": "PUT", "filename": filename, "keywords": keywords})
    recv_ack(sock)

    index = load_index()
    blocks = []

    with open(filepath, 'rb') as f:
        while chunk := f.read(BLOCK_SIZE):
            nonce, ciphertext, tag = encrypt_block(MASTER_KEY, chunk)
            block_name = name_from_ciphertext(ciphertext)
            store_block_rpc(sock, block_name, nonce, ciphertext, tag)
            blocks.append(block_name)

    
    enc_file_id = encrypt_file_id(filename)
    for i, kw in enumerate(keywords):
        token = token_from_keyword(SEARCH_KEY, kw)
        msg = {"op": "STORE_TOKEN", "token": token, "file_id": enc_file_id}
        if i == 0:
            msg["block_ids"] = blocks  
        send_json(sock, msg)
        recv_ack(sock)

    index[filename] = {"blocks": blocks, "keywords": keywords}
    save_index(index)
    print(f"File '{filename}' uploaded successfully ({len(blocks)} blocks).")

def get_by_keyword(sock, keyword, out_dir):
    
    os.makedirs(out_dir, exist_ok=True)
    token = token_from_keyword(SEARCH_KEY, keyword)
    send_json(sock, {"op": "GET", "token": token})

    buffer = ""
    current_id = None
    chunks = []

    def flush():
        nonlocal current_id, chunks
        if current_id and chunks:
            try:
                fname = decrypt_file_id(current_id)
            except Exception:
                fname = f"{current_id[:8]}.bin"
            out_path = os.path.join(out_dir, os.path.basename(fname))
            with open(out_path, "wb") as f:
                for b in chunks:
                    f.write(b)
            print(f"[OK] {fname} ({len(chunks)} blocks)")
        current_id, chunks = None, []

    seen_end = False
    while not seen_end:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data.decode()
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            op = obj.get("op")
            if op == "FILE_ID":
                flush()
                current_id = obj["file_id"]
                continue
            if op == "FILE_END":
                flush()
                continue
            if op == "GET_END":
                flush()
                seen_end = True
                break

            try:
                nonce = bytes.fromhex(obj["nonce"])
                ciphertext = bytes.fromhex(obj["ciphertext"])
                tag = bytes.fromhex(obj["tag"])
                pt = decrypt_block(MASTER_KEY, nonce, ciphertext, tag)
                chunks.append(pt)
            except Exception as e:
                print(f"[WARN] block failed: {e}")
                

    print("[DONE] Keyword download finished.")

def get_file(sock):
    filename = input("Enter filename or keyword to download: ").strip()
    index = load_index()
    entry = index.get(filename)

    if not entry or not entry.get("blocks"):
        
        ok = get_by_keyword(sock, filename, "client/downloads")
        if not ok:
            print(f"[ERROR] '{filename}' not found in local index and no file was obtained by keyword.")
            if index:
                print("Available files:")
                for name, meta in index.items():
                    print(f" - {name} ({len(meta.get('blocks', []))} blocks)")
        return

    block_ids = entry["blocks"]
    send_json(sock, {"op": "GET", "filename": filename, "block_ids": block_ids})

    buffer = ""
    blocks = []
    seen_end = False

    while not seen_end:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data.decode()

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(obj, dict) and obj.get("op") == "GET_END":
                seen_end = True
                break

            try:
                nonce = bytes.fromhex(obj["nonce"])
                ciphertext = bytes.fromhex(obj["ciphertext"])
                tag = bytes.fromhex(obj["tag"])
            except KeyError:
                print(f"[ERROR] Unexpected message: {obj}")
                return

            try:
                plaintext = decrypt_block(MASTER_KEY, nonce, ciphertext, tag)
            except Exception as e:
                print(f"[ERROR] Block {obj.get('block_id','?')} failed integrity check: {e}")
                return

            blocks.append(plaintext)

    expected = len(block_ids)
    if len(blocks) != expected:
        print(f"[ERROR] Expected {expected} blocks, received {len(blocks)}. Aborting without writing file.")
        return

    os.makedirs("client/downloads", exist_ok=True)
    out_path = os.path.join("client/downloads", filename)
    with open(out_path, "wb") as f:
        for blk in blocks:
            f.write(blk)

    print(f"File '{filename}' downloaded successfully ({len(blocks)} blocks) into 'client/downloads/'.")

def check_integrity(sock, filename):
  
    index = load_index()
    entry = index.get(filename)
    if not entry:
        print(f"[ERROR] '{filename}' does not exist in local index.")
        return
    block_ids = entry.get("blocks", [])
    keywords  = entry.get("keywords", [])

    
    if not block_ids:
        print(f"[ERROR] '{filename}' has no block_ids in local index.")
        return

    send_json(sock, {"op": "GET", "filename": filename, "block_ids": block_ids})

    ok_blocks, total_blocks = 0, 0
    buffer = ""
    seen_end = False
    while not seen_end:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data.decode()

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if obj.get("op") == "GET_END":
                seen_end = True
                break

           
            try:
                nonce = bytes.fromhex(obj["nonce"])
                ciphertext = bytes.fromhex(obj["ciphertext"])
                tag = bytes.fromhex(obj["tag"])
            except KeyError:
                print(f"[FAIL] Unexpected message in GET: {obj}")
                continue

            total_blocks += 1
            try:
                _ = decrypt_block(MASTER_KEY, nonce, ciphertext, tag)
                ok_blocks += 1
            except Exception as e:
                print(f"[FAIL] Block {obj.get('block_id','?')} invalid: {e}")

    print(f"[CHECK-BLOCKS] {ok_blocks}/{total_blocks} blocks valid.")

   
    if not keywords:
        print("[CHECK-KEYWORDS] (no keywords stored locally)")
        print(f"[CHECK] Summary: blocks {ok_blocks}/{total_blocks}; keywords 0/0 OK")
        return

    ok_kw = 0
    for kw in keywords:
        token = token_from_keyword(SEARCH_KEY, kw)
        send_json(sock, {"op": "SEARCH", "token": token})

       
        buf = ""
        while "\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                print(f"[FAIL] Connection closed during SEARCH for keyword '{kw}'.")
                break
            buf += chunk.decode()
        if "\n" not in buf:
            print(f"[FAIL] Incomplete response for keyword '{kw}'.")
            continue

        line, _ = buf.split("\n", 1)
        try:
            enc_list = json.loads(line)
            if not isinstance(enc_list, list):
                print(f"[FAIL] Unexpected format in SEARCH for '{kw}'.")
                continue
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON in SEARCH for '{kw}'.")
            continue

        found_this_file = False
        for enc_hex in enc_list:
            try:
                name = decrypt_file_id(enc_hex)
                if os.path.basename(name) == os.path.basename(filename):
                    found_this_file = True
                    break
            except Exception:
               
                continue

        if found_this_file:
            print(f"[CHECK-KEYWORD] '{kw}': OK (token references '{filename}').")
            ok_kw += 1
        else:
            print(f"[CHECK-KEYWORD] '{kw}': MISSING (token does not reference '{filename}').")

    print(f"[CHECK] Summary: blocks {ok_blocks}/{total_blocks}; keywords {ok_kw}/{len(keywords)} OK")


def list_files(sock):
    index = load_index()
    if not index:
        print("(No files in local index)")
        return
    print("Files in local index:")
    for fname in index:
        print(f" - {fname} ({len(index[fname]['blocks'])} blocks)")

def search_files(sock):
    keyword = input("Enter keyword to search: ")
    token = token_from_keyword(SEARCH_KEY, keyword)
    send_json(sock, {"op": "SEARCH", "token": token})

    buffer = ""
    while "\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            print("Connection closed by server.")
            return
        buffer += chunk.decode()

    line, _ = buffer.split("\n", 1)
    try:
        enc_list = json.loads(line)
        if not isinstance(enc_list, list):
            print("Unexpected search response format.")
            return

        file_ids = []
        for enc_hex in enc_list:
            try:
                file_ids.append(decrypt_file_id(enc_hex))
            except Exception as e:
                print(f"Failed to decrypt one file_id: {e}")

        print("Search results:")
        print(", ".join(file_ids) if file_ids else "(No files found)")
    except json.JSONDecodeError:
        print("Invalid JSON in search response.")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to server.")

    while True:
        print("\nMenu:")
        print("1. Upload file (PUT)")
        print("2. Download file (GET)")
        print("3. List files")
        print("4. Search files")
        print("5. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            put_file(sock)
        elif choice == '2':
            get_file(sock)
        elif choice == '3':
            list_files(sock)
        elif choice == '4':
            search_files(sock)
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

    sock.close()

if __name__ == "__main__":
    main()
