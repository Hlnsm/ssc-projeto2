#!/usr/bin/env python3


import os
import threading
import argparse
import time
import json

from client.obss_gateway import (
    encrypt_block,
    name_from_ciphertext,
    encrypt_file_id,
    token_from_keyword,
    _connect_obss,
    _send_json,
    _recv_ack,
    MASTER_KEY,
    SEARCH_KEY,
    BLOCK_SIZE,
)

# Pequeno helper para criar payload sintético
def make_payload(size_bytes: int) -> bytes:
   
    return (b"X" * size_bytes)


def put_synthetic_file(thread_id: int, file_index: int, block_size: int, keywords: list[str]) -> None:
    
    filename = f"concurrent_{thread_id}_{file_index}.bin"
    content = make_payload(block_size * 2)  

    try:
        sock = _connect_obss()
    except Exception as e:
        print(f"[T{thread_id}] Erro a ligar ao OBSS: {e}")
        return

    try:
       
        msg_put = {
            "op": "PUT",
            "filename": filename,
            "keywords": keywords,
        }
        _send_json(sock, msg_put)
        _recv_ack(sock)

        blocks = []

        
        offset = 0
        while offset < len(content):
            chunk = content[offset : offset + block_size]
            offset += block_size

            nonce, ciphertext, tag = encrypt_block(MASTER_KEY, chunk)
            block_id = name_from_ciphertext(ciphertext)

            msg_block = {
                "op": "STORE_BLOCK",
                "block_id": block_id,
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
            }
            _send_json(sock, msg_block)
            _recv_ack(sock)

            blocks.append(block_id)

        
        enc_file_id = encrypt_file_id(filename)

        
        for i, kw in enumerate(keywords):
            token = token_from_keyword(SEARCH_KEY, kw)
            msg_token = {
                "op": "STORE_TOKEN",
                "token": token,
                "file_id": enc_file_id,
            }
            if i == 0:
                msg_token["block_ids"] = blocks

            _send_json(sock, msg_token)
            _recv_ack(sock)

        print(f"[T{thread_id}] PUT OK: {filename} ({len(blocks)} blocos)")

    except Exception as e:
        print(f"[T{thread_id}] Erro durante PUT: {e}")
    finally:
        sock.close()


def worker(thread_id: int, files_per_thread: int, block_size: int, keywords: list[str]) -> None:
    for i in range(files_per_thread):
        put_synthetic_file(thread_id, i, block_size, keywords)


def main():
    parser = argparse.ArgumentParser(description="Teste de concorrência ao OBSS")
    parser.add_argument("--threads", type=int, default=5, help="Número de threads concorrentes")
    parser.add_argument("--files-per-thread", type=int, default=3, help="Número de ficheiros por thread")
    parser.add_argument("--block-size", type=int, default=None, help="Tamanho de bloco em bytes (default = BLOCK_SIZE do sistema)")
    parser.add_argument("--keywords", nargs="*", default=["stress", "test"], help="Keywords a usar nos PUTs")

    args = parser.parse_args()

    block_size = args.block_size or BLOCK_SIZE

    print("=== Teste de concorrência OBSS ===")
    print(f"Threads           : {args.threads}")
    print(f"Ficheiros/thread  : {args.files_per_thread}")
    print(f"Block size (bytes): {block_size}")
    print(f"Keywords          : {args.keywords}")
    print()

    threads = []
    start = time.time()
    for t_id in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(t_id, args.files_per_thread, block_size, args.keywords),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    elapsed = time.time() - start
    print(f"\n[RESULTADO] Concluído em {elapsed:.2f} segundos.")


if __name__ == "__main__":
    main()
