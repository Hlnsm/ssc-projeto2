# client/obss_gateway.py

import os
import socket
import json
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OBSS_HOST = "127.0.0.1"
OBSS_PORT = 5500

HERE = os.path.dirname(__file__)         
PROJECT_ROOT = os.path.dirname(HERE)      




CLIENT_SECAO = os.environ.get("CLIENT_SECAO", "default")


DOWNLOADS_BASE_DIR = os.path.join(PROJECT_ROOT, "client", "downloads", CLIENT_SECAO)



def load_crypto_config():
    
    config = {}

    candidates = [
        os.path.join(PROJECT_ROOT, "cryptoconfig.txt"),
        os.path.join(HERE, "cryptoconfig.txt"),
    ]

    cfg_path = None
    for p in candidates:
        if os.path.exists(p):
            cfg_path = p
            break

    if cfg_path is None:
        raise FileNotFoundError(
            "cryptoconfig.txt não encontrado nem na raiz do projeto nem em client/.\n"
            "Coloca-o em 'projeto/cryptoconfig.txt' ou 'projeto/client/cryptoconfig.txt'."
        )

    with open(cfg_path, encoding="utf-8") as f:
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
DEDUP_ON = str(crypto_cfg.get("DEDUP", "ON")).strip().upper() in ("ON", "1", "TRUE", "YES")

BLOCK_SIZE = crypto_cfg.get("BLOCKSIZE_INT", 1024)
KEYSIZE_BYTES = (crypto_cfg.get("KEYSIZE_INT", 256)) // 8


def load_key(rel_path: str) -> bytes:
    
    candidates = [
        os.path.join(PROJECT_ROOT, rel_path),
        os.path.join(HERE, rel_path),
    ]

    path = None
    for p in candidates:
        if os.path.exists(p):
            path = p
            break

    if path is None:
        raise FileNotFoundError(
            f"Chave não encontrada em {rel_path} (nem em raiz nem em client/).\n"
            f"Coloca por exemplo em 'client/{rel_path}'."
        )

    with open(path, "r", encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())



MASTER_KEY = load_key("keys/enc_key.txt")
SEARCH_KEY = load_key("keys/mac_key.txt")  
NAME_KEY = SEARCH_KEY  


def assert_len(name: str, key: bytes, expected: int):
    if len(key) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(key)}.")


assert_len("MASTER_KEY", MASTER_KEY, KEYSIZE_BYTES)
assert_len("SEARCH_KEY", SEARCH_KEY, 32)



OBSS_INDEX_PATH = os.path.join(PROJECT_ROOT, "client", "index", CLIENT_SECAO, "client_index.json")


def load_index() -> dict:
    os.makedirs(os.path.dirname(OBSS_INDEX_PATH), exist_ok=True)
    if os.path.exists(OBSS_INDEX_PATH):
        with open(OBSS_INDEX_PATH, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_index(index: dict) -> None:
    os.makedirs(os.path.dirname(OBSS_INDEX_PATH), exist_ok=True)
    with open(OBSS_INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)




def encrypt_block(key: bytes, plaintext: bytes):
    
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
    
    return hmac.new(key, keyword.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt_file_id(file_id: str) -> str:
    
    aesgcm = AESGCM(SEARCH_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, file_id.encode("utf-8"), None)
    return (nonce + ct).hex()


def decrypt_file_id(enc_hex: str) -> str:
   
    data = bytes.fromhex(enc_hex)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(SEARCH_KEY)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")




def _connect_obss() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((OBSS_HOST, OBSS_PORT))
    return s


def _send_json(sock: socket.socket, message: dict) -> None:
    data = json.dumps(message) + "\n"
    sock.sendall(data.encode("utf-8"))


def _recv_ack(sock: socket.socket) -> None:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(16)
        if not chunk:
            break
        buf += chunk
    if buf.strip() != b"ACK":
        print(f"[OBSS][WARN] Unexpected ACK: {buf!r}")


def _store_block_rpc(sock: socket.socket, block_name: str, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
    payload = {
        "op": "STORE_BLOCK",
        "block_id": block_name,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }
    _send_json(sock, payload)
    _recv_ack(sock)



def obss_put_file() -> None:
    
    filepath = input("Caminho do ficheiro a enviar (PUT): ").strip()
    if not os.path.exists(filepath):
        print("[OBSS] Ficheiro não existe.")
        return

    filename = os.path.basename(filepath)
    keywords_line = input("Palavras-chave para pesquisa (separadas por espaço): ").strip()
    if not keywords_line:
        print("[OBSS] Não foram indicadas keywords (podes adicionar manualmente depois, se quiseres).")
        keywords = []
    else:
        keywords = keywords_line.split()

    try:
        sock = _connect_obss()
    except Exception as e:
        print(f"[OBSS] Erro a ligar ao servidor OBSS: {e}")
        return

    try:
        
        _send_json(sock, {"op": "PUT", "filename": filename, "keywords": keywords})
        _recv_ack(sock)

        index = load_index()
        blocks = []

        
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(BLOCK_SIZE)
                if not chunk:
                    break
                nonce, ciphertext, tag = encrypt_block(MASTER_KEY, chunk)
                block_name = name_from_ciphertext(ciphertext)
                _store_block_rpc(sock, block_name, nonce, ciphertext, tag)
                blocks.append(block_name)

        
        enc_file_id = encrypt_file_id(filename)

        
        for i, kw in enumerate(keywords):
            token = token_from_keyword(SEARCH_KEY, kw)
            msg = {
                "op": "STORE_TOKEN",
                "token": token,
                "file_id": enc_file_id,
            }
            if i == 0:
                
                msg["block_ids"] = blocks
            _send_json(sock, msg)
            _recv_ack(sock)

        
        index[filename] = {
            "blocks": blocks,
            "keywords": keywords,
            "file_id": enc_file_id,
        }
        save_index(index)

        print(f"[OBSS] Seção        : {CLIENT_SECAO}")
        print(f"[OBSS] Ficheiro     : '{filename}' enviado com sucesso ({len(blocks)} blocos).")
        print(f"[OBSS] file_id (anon): {enc_file_id[:32]}...")
        print(f"[OBSS] Índice em     : {OBSS_INDEX_PATH}")
    finally:
        sock.close()


def _get_by_keyword(sock: socket.socket, keyword: str, auth_token: str | None, out_dir: str) -> None:
    
    if not auth_token:
        print("[OBSS] Não tens token de autenticação (JWT do OAS). Faz login primeiro.")
        return

    os.makedirs(out_dir, exist_ok=True)

    search_token = token_from_keyword(SEARCH_KEY, keyword)

    
    payload = {
        "op": "GET",
        
        "token": search_token,
        
        "search_token": search_token,
        "auth_token": auth_token,
    }

    print(
        f"[OBSS][DEBUG] GET keyword='{keyword}', search_token={search_token[:16]}..., "
        f"auth={'yes' if auth_token else 'no'}"
    )

    _send_json(sock, payload)

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
            print(f"[OBSS][OK] {fname} ({len(chunks)} blocos) -> {out_path}")
        current_id, chunks = None, []

    seen_end = False
    while not seen_end:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data.decode("utf-8", errors="ignore")

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(f"[OBSS][DEBUG] JSON inválido em linha de GET: {line}")
                continue

            op = obj.get("op")
            if op == "FILE_ID":
                flush()
                current_id = obj.get("file_id")
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
            except KeyError:
               
                print(f"[OBSS][DEBUG] Mensagem inesperada em GET keyword: {obj}")
            except Exception as e:
                print(f"[OBSS][WARN] bloco falhou: {e}")

    print("[OBSS] Download por keyword terminado.")




def _get_file_by_name(sock: socket.socket, filename: str) -> None:
   
    index = load_index()
    entry = index.get(filename)
    if not entry or not entry.get("blocks"):
        print(f"[OBSS] '{filename}' não existe no índice local da seção {CLIENT_SECAO}.")
        return

    block_ids = entry["blocks"]
    _send_json(sock, {"op": "GET", "filename": filename, "block_ids": block_ids})

    buffer = ""
    blocks = []
    seen_end = False

    while not seen_end:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data.decode("utf-8", errors="ignore")

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
                print(f"[OBSS][ERROR] Mensagem inesperada em GET: {obj}")
                return

            try:
                plaintext = decrypt_block(MASTER_KEY, nonce, ciphertext, tag)
            except Exception as e:
                print(f"[OBSS][ERROR] Bloco {obj.get('block_id','?')} falhou integridade: {e}")
                return

            blocks.append(plaintext)

    expected = len(block_ids)
    if len(blocks) != expected:
        print(f"[OBSS][ERROR] Esperava {expected} blocos, recebi {len(blocks)}. Não escrevo ficheiro.")
        return

    
    out_dir = DOWNLOADS_BASE_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, filename)
    with open(out_path, "wb") as f:
        for blk in blocks:
            f.write(blk)

    print(f"[OBSS] Ficheiro '{filename}' descarregado para '{out_dir}/' ({len(blocks)} blocos).")


def obss_get_file(auth_token: str | None) -> None:
   
    target = input("Nome do ficheiro OU keyword para download (GET): ").strip()
    if not target:
        print("[OBSS] Input vazio.")
        return

    index = load_index()
    has_local = target in index

    try:
        sock = _connect_obss()
    except Exception as e:
        print(f"[OBSS] Erro a ligar ao servidor OBSS: {e}")
        return

    try:
        if has_local:
            _get_file_by_name(sock, target)
        else:
            print(f"[OBSS] '{target}' não está no índice local da seção {CLIENT_SECAO}.")
            print("[OBSS] A tratar o input como keyword para GET por keyword.")
            out_dir = DOWNLOADS_BASE_DIR
            _get_by_keyword(sock, target, auth_token, out_dir=out_dir)
    finally:
        sock.close()


def obss_search_files(auth_token: str | None) -> None:
    
    if not auth_token:
        print("[OBSS] Não tens token de autenticação (JWT do OAS). Faz login primeiro.")
        return

    keyword = input("Keyword para SEARCH no OBSS: ").strip()
    if not keyword:
        print("[OBSS] Keyword vazia.")
        return

    search_token = token_from_keyword(SEARCH_KEY, keyword)
   
    print(f"[OBSS][DEBUG] SEARCH keyword='{keyword}', search_token={search_token[:16]}...")

    try:
        sock = _connect_obss()
    except Exception as e:
        print(f"[OBSS] Erro a ligar ao servidor OBSS: {e}")
        return

    try:
       
        _send_json(sock, {
            "op": "SEARCH",
            "search_token": search_token,
            "auth_token": auth_token,
        })

        buffer = ""
        while "\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                print("[OBSS] Conexão fechada pelo servidor durante SEARCH.")
                return
            buffer += chunk.decode("utf-8", errors="ignore")

        line, _ = buffer.split("\n", 1)
        print(f"[OBSS][DEBUG] SEARCH raw response line: {line}")

        try:
            enc_list = json.loads(line)
            if not isinstance(enc_list, list):
                print("[OBSS] Formato inesperado na resposta de SEARCH.")
                print(f"[OBSS][DEBUG] Tipo recebido: {type(enc_list)}")
                return

            print(f"[OBSS][DEBUG] Nº de file_ids cifrados recebidos: {len(enc_list)}")

            file_ids = []
            for i, enc_hex in enumerate(enc_list):
                try:
                    name = decrypt_file_id(enc_hex)
                    file_ids.append(name)
                except Exception as e:
                    print(f"[OBSS][WARN] Falha a decifrar file_id[{i}]: {e}")

            print("[OBSS] Resultados da pesquisa:")
            if file_ids:
                for name in file_ids:
                    print(f"  - {name}")
            else:
                print("  (sem ficheiros)")
        except json.JSONDecodeError as e:
            print("[OBSS] JSON inválido na resposta de SEARCH.")
            print(f"[OBSS][DEBUG] Erro JSON: {e}")
    finally:
        sock.close()


def obss_list_local_files() -> None:
   
    index = load_index()
    if not index:
        print("[OBSS] Índice local vazio.")
        print(f"[OBSS] Caminho do índice desta seção: {OBSS_INDEX_PATH}")
        return

    print(f"[OBSS] Ficheiros no índice local (seção {CLIENT_SECAO}):")
    for fname, meta in index.items():
        blocks = meta.get("blocks", [])
        file_id = meta.get("file_id", "")
        print(f"  - {fname} ({len(blocks)} blocos)")
        if file_id:
            print(f"      file_id: {file_id[:32]}...")


def obss_get_local_file_id(filename: str) -> str | None:
    
    index = load_index()
    entry = index.get(filename)
    if not entry:
        return None
    return entry.get("file_id")
