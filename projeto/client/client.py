#!/usr/bin/env python3
import os
import socket
import getpass
import base64
import json

from common.protocol import make_request

# Cripto do lado do cliente (OAS/OAMS)
from client.crypto_client import (
    generate_user_keypair,
    export_private_key_pem,
    import_private_key_pem,
    export_public_key_raw_b64,
    make_hpw_record,
    sign_body_json_b64,
    sha256_hex,
    compute_hpw,
    sign_bytes_b64,
    build_auth_message,
    verify_oas_response_signature,
    verify_oas_jwt,
    parse_hpw_record,
    verify_hpw_local,
    make_hpw_record,
    compute_hpw
    

)


from client.obss_gateway import (
    obss_put_file,
    obss_get_file,
    obss_search_files,
    obss_list_local_files,
    obss_get_local_file_id,
)





OAS_HOST = "127.0.0.1"
OAS_PORT = 6000

OAMS_HOST = "127.0.0.1"
OAMS_PORT = 6001


CLIENT_SECAO = os.environ.get("CLIENT_SECAO", "default")

CLIENT_KEYS_BASE_DIR = os.path.join("client", "keys")
CLIENT_KEYS_DIR = os.path.join(CLIENT_KEYS_BASE_DIR, CLIENT_SECAO)
CLIENT_PRIV_KEY_PATH = os.path.join(CLIENT_KEYS_DIR, "priv_key.pem")
CLIENT_PUB_KEY_PATH = os.path.join(CLIENT_KEYS_DIR, "pub_key.b64")
CLIENT_HPW_META_PATH = os.path.join(CLIENT_KEYS_DIR, "hpw_meta.txt")
CLIENT_TOKEN_PATH = os.path.join(CLIENT_KEYS_DIR, "oas_token.txt")



OAS_PUB_KEY_B64 = "GaICAzgTOEiGs+TQryUhu7jkZ59wrZgu5xh3Jv8906w="




def ensure_keys_dir():
    os.makedirs(CLIENT_KEYS_DIR, exist_ok=True)


def save_user_keys(priv_key, pub_key_b64):
   
    ensure_keys_dir()

    priv_pem = export_private_key_pem(priv_key)
    with open(CLIENT_PRIV_KEY_PATH, "wb") as f:
        f.write(priv_pem)

    with open(CLIENT_PUB_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(pub_key_b64)


def load_or_create_user_keys():
    
    ensure_keys_dir()

    if not (os.path.exists(CLIENT_PRIV_KEY_PATH) and os.path.exists(CLIENT_PUB_KEY_PATH)):
        priv, pub = generate_user_keypair()
        pub_b64 = export_public_key_raw_b64(pub)
        save_user_keys(priv, pub_b64)

    with open(CLIENT_PRIV_KEY_PATH, "rb") as f:
        priv_pem = f.read()
    priv_key = import_private_key_pem(priv_pem)

    with open(CLIENT_PUB_KEY_PATH, "r", encoding="utf-8") as f:
        pub_key_b64 = f.read().strip()

    return priv_key, pub_key_b64


def load_oas_token():
    
    if not os.path.exists(CLIENT_TOKEN_PATH):
        print("[CLIENT] Erro: ainda não tens token. Faz login primeiro (opção 2).")
        return None

    with open(CLIENT_TOKEN_PATH, "r", encoding="utf-8") as f:
        token = f.read().strip()

    if not token:
        print("[CLIENT] Erro: ficheiro de token está vazio.")
        return None

    return token





def connect_oas():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((OAS_HOST, OAS_PORT))
    return sock


def connect_oams():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((OAMS_HOST, OAMS_PORT))
    return sock


def send_json_line(sock: socket.socket, msg: dict):
    
    line = json.dumps(msg) + "\n"
    sock.sendall(line.encode("utf-8"))


def recv_json_line(sock: socket.socket):
   
    buffer = ""
    while "\n" not in buffer:
        data = sock.recv(4096)
        if not data:
            if not buffer:
                return None
            break
        buffer += data.decode("utf-8", errors="ignore")

    line, _sep, _rest = buffer.partition("\n")
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None



#REGISTO NO OAS


def oas_create_registration():
    
    priv_key, pub_key_b64 = load_or_create_user_keys()
    print("[CLIENT] Secção :", CLIENT_SECAO)
    print("[CLIENT] Public key (b64):", pub_key_b64)

    print("=== REGISTO NO OAS ===")
    email = input("Email (opcional, só para atributos / demo): ").strip()
    pwd1 = getpass.getpass("Password: ")
    pwd2 = getpass.getpass("Confirmar password: ")

    if pwd1 != pwd2:
        print("[CLIENT] Erro: passwords não coincidem.")
        return

    

    attrs = {}
    if email:
        attrs["email"] = sha256_hex(email.encode("utf-8"))

    
    
    pwd_record = make_hpw_record(pwd1)
    
    
    algorithm, iterations, salt, hpw_bytes = parse_hpw_record(pwd_record)
    
    print(f"[CLIENT] Password hash: {algorithm} com {iterations} iterações")
    print(f"[CLIENT] Salt: {salt.hex()[:16]}...")
    print(f"[CLIENT] HPW:  {hpw_bytes.hex()[:16]}...")

    
    ensure_keys_dir()
    with open(CLIENT_HPW_META_PATH, "w", encoding="utf-8") as f:
        f.write(pwd_record)  

    
    body = {
        "pub_key": pub_key_b64,
        "pwd_hash": hpw_bytes.hex(),  
        "attrs": attrs,
    }

    sig = sign_body_json_b64(priv_key, body)

    req = make_request(
        op="CreateRegistration",
        body=body,
        sig=sig,
        token=None,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAS não respondeu.")
        return

    status = resp.get("status")
    body_resp = resp.get("body", {})
    error = resp.get("error")

    if status == "OK":
        anon_id = body_resp.get("anon_id")
        print("[CLIENT] Registo criado com sucesso!")
        print("         anon_id:", anon_id)
        print(f"         Password: PBKDF2-SHA256 com {iterations} iterações ")
    else:
        print("[CLIENT] Falha no registo.")
        print("         status:", status)
        print("         error :", error)
        print("         body  :", body_resp)




def oas_authenticate():
 
    priv_key, pub_key_b64 = load_or_create_user_keys()

    if not os.path.exists(CLIENT_HPW_META_PATH):
        print("[CLIENT] Erro: não há dados de password guardados. Faz primeiro o registo.")
        return

   
    with open(CLIENT_HPW_META_PATH, "r", encoding="utf-8") as f:
        pwd_record = f.read().strip()

    if not pwd_record:
        print("[CLIENT] Erro: ficheiro de password vazio ou inválido. Refaz o registo.")
        return

    
    try:
        algorithm, iterations, salt, stored_hpw = parse_hpw_record(pwd_record)
        print(f"[CLIENT] Carregado: {algorithm} com {iterations} iterações")
    except Exception as e:
        print(f"[CLIENT] Erro ao fazer parse do record de password: {e}")
        print("[CLIENT] Refaz o registo.")
        return

    print("=== AUTH NO OAS ===")
    pwd = getpass.getpass("Password: ")
    
    
    hpw_bytes = compute_hpw(pwd, salt, iterations)
    hpw_hex = hpw_bytes.hex()
    
    
    if verify_hpw_local(pwd, pwd_record):
        print("[CLIENT]   Password verificada localmente")
    else:
        print("[CLIENT]  Password não corresponde ao hash guardado")
        print("[CLIENT] Continuando mesmo assim (servidor decidirá)...")

    ctx = "login"

    
    body_start = {
        "pub_key": pub_key_b64,
        "ctx": ctx,
    }
    sig_start = sign_body_json_b64(priv_key, body_start)

    req_start = make_request(
        op="AuthStart",
        body=body_start,
        sig=sig_start,
        token=None,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req_start)
            resp_challenge = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp_challenge is None:
        print("[CLIENT] OAS não respondeu ao AuthStart.")
        return

    if not verify_oas_response_signature(resp_challenge, OAS_PUB_KEY_B64):
        print("[CLIENT] ERRO: assinatura da AuthChallenge é inválida!")
        return

    if resp_challenge.get("status") != "OK" or resp_challenge.get("op") != "AuthChallenge":
        print("[CLIENT] AuthStart falhou.")
        print("         status:", resp_challenge.get("status"))
        print("         error :", resp_challenge.get("error"))
        return

    body_ch = resp_challenge.get("body", {})
    challenge_id = body_ch.get("challenge_id")
    nonce_b64 = body_ch.get("nonce")
    ts = body_ch.get("ts")
    ctx_resp = body_ch.get("ctx")

    if not challenge_id or not nonce_b64 or ts is None:
        print("[CLIENT] Challenge inválido.")
        return

    print("[CLIENT] Challenge recebido do OAS:")
    print("         challenge_id:", challenge_id)
    print("         nonce       :", nonce_b64)
    print("         ts          :", ts)
    print("         ctx         :", ctx_resp)

    nonce_bytes = base64.b64decode(nonce_b64)

    
    m_bytes = build_auth_message(nonce_bytes, ts, ctx_resp, hpw_bytes)
    sig_m_b64 = sign_bytes_b64(priv_key, m_bytes)

    body_resp = {
        "pub_key": pub_key_b64,
        "challenge_id": challenge_id,
        "sig_m": sig_m_b64,
        "pw_proof": hpw_hex, 
    }

    sig_resp = sign_body_json_b64(priv_key, body_resp)

    req_resp = make_request(
        op="AuthResponse",
        body=body_resp,
        sig=sig_resp,
        token=None,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req_resp)
            resp_final = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp_final is None:
        print("[CLIENT] OAS não respondeu ao AuthResponse.")
        return

    if not verify_oas_response_signature(resp_final, OAS_PUB_KEY_B64):
        print("[CLIENT] ERRO: assinatura da AuthResult é inválida!")
        return

    if resp_final.get("status") != "OK" or resp_final.get("op") != "AuthResult":
        print("[CLIENT] Autenticação falhou.")
        print("         status:", resp_final.get("status"))
        print("         error :", resp_final.get("error"))
        return

    body_final = resp_final.get("body", {})
    token = body_final.get("token")
    exp = body_final.get("expires_at")

    if not token:
        print("[CLIENT] ERRO: resposta do OAS não contém token.")
        return

    try:
        header, payload = verify_oas_jwt(token, OAS_PUB_KEY_B64)
    except Exception as e:
        print("[CLIENT] ERRO: token JWT inválido ou assinatura incorreta.")
        print("       Detalhe:", e)
        return

    print("[CLIENT] Autenticação bem sucedida!  ")
    print("         Secção      :", CLIENT_SECAO)
    print("         Token (JWT):", token[:50] + "...")
    print("         Expira em  :", exp)
    print(f"         Password   : PBKDF2-SHA256 com {iterations} iterações  ")
    print("         JWT header :", header)
    print("         JWT claims :", payload)

    try:
        ensure_keys_dir()
        with open(CLIENT_TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(token)
        print(f"[CLIENT] Token guardado em {CLIENT_TOKEN_PATH}")
    except Exception as e:
        print("[CLIENT] Aviso: não consegui guardar o token em ficheiro:", e)



def oas_get_my_registration():
    token = load_oas_token()
    if not token:
        return

    req = make_request(
        op="GetMyRegistration",
        body={},
        sig=None,
        token=token,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAS não respondeu ao GetMyRegistration.")
        return

    if not verify_oas_response_signature(resp, OAS_PUB_KEY_B64):
        print("[CLIENT] ERRO: assinatura da resposta do OAS é inválida!")
        return

    if resp.get("status") != "OK":
        print("[CLIENT] GetMyRegistration falhou.")
        print("         status:", resp.get("status"))
        print("         error :", resp.get("error"))
        return

    body = resp.get("body", {})
    print("=== OS MEUS DADOS NO OAS ===")
    print("seção   :", CLIENT_SECAO)
    print("anon_id :", body.get("anon_id"))
    print("pub_key :", body.get("pub_key"))
    print("status  :", body.get("status"))
    print("created :", body.get("created_at"))
    print("attrs   :", body.get("attrs"))


def oas_delete_registration():
    token = load_oas_token()
    if not token:
        return

    print("=== APAGAR REGISTO NO OAS ===")
    print("Isto vai desativar a tua conta no OAS (status=deleted).")
    conf = input("Tens a certeza? (escreve 'SIM' para confirmar): ").strip()
    if conf != "SIM":
        print("[CLIENT] Operação cancelada.")
        return

    priv_key, _ = load_or_create_user_keys()

    body = {"confirm": True}
    sig = sign_body_json_b64(priv_key, body)

    req = make_request(
        op="DeleteRegistration",
        body=body,
        sig=sig,
        token=token,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAS não respondeu ao DeleteRegistration.")
        return

    if not verify_oas_response_signature(resp, OAS_PUB_KEY_B64):
        print("[CLIENT] ERRO: assinatura da resposta do OAS é inválida!")
        return

    if resp.get("status") != "OK":
        print("[CLIENT] DeleteRegistration falhou.")
        print("         status:", resp.get("status"))
        print("         error :", resp.get("error"))
        return

    body_resp = resp.get("body", {})
    print("[CLIENT] Registo apagado (logical delete) com sucesso!")
    print("         anon_id:", body_resp.get("anon_id"))
    print("         status :", body_resp.get("status"))


def oas_modify_registration():
    
    token = load_oas_token()
    if not token:
        return

    priv_key, _ = load_or_create_user_keys()

    print("=== MODIFICAR REGISTO NO OAS ===")
    print("1) Alterar email")
    print("2) Alterar password")
    print("0) Voltar")
    choice = input("> ").strip()

    new_attrs = {}
    new_pwd_hpw = None

    if choice == "1":
        new_email = input("Novo email: ").strip()
        if not new_email:
            print("[CLIENT] Email vazio, a cancelar.")
            return
        new_attrs["email"] = sha256_hex(new_email.encode("utf-8"))

    elif choice == "2":
        print("=== ALTERAR PASSWORD ===")
        pwd1 = getpass.getpass("Nova password: ")
        pwd2 = getpass.getpass("Confirmar nova password: ")

        if pwd1 != pwd2:
            print("[CLIENT] Erro: passwords não coincidem.")
            return

        
        pwd_record = make_hpw_record(pwd1)
        algorithm, iterations, salt, hpw_bytes = parse_hpw_record(pwd_record)
        
        new_pwd_hpw = hpw_bytes.hex()

        
        with open(CLIENT_HPW_META_PATH, "w", encoding="utf-8") as f:
            f.write(pwd_record)

        print(f"[CLIENT] Nova password preparada: {algorithm} com {iterations} iterações  ")
        print("[CLIENT] Record atualizado localmente.")

    elif choice == "0":
        return
    else:
        print("[CLIENT] Opção inválida.")
        return

    if not new_attrs and not new_pwd_hpw:
        print("[CLIENT] Nada para atualizar.")
        return

    body = {}
    if new_attrs:
        body["new_attrs"] = new_attrs
    if new_pwd_hpw:
        body["new_pwd_hpw"] = new_pwd_hpw

    sig = sign_body_json_b64(priv_key, body)

    req = make_request(
        op="ModifyRegistration",
        body=body,
        sig=sig,
        token=token,
    )

    try:
        with connect_oas() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAS em {OAS_HOST}:{OAS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAS não respondeu ao ModifyRegistration.")
        return

    if not verify_oas_response_signature(resp, OAS_PUB_KEY_B64):
        print("[CLIENT] ERRO: assinatura da resposta do OAS é inválida!")
        return

    if resp.get("status") != "OK":
        print("[CLIENT] ModifyRegistration falhou.")
        print("         status:", resp.get("status"))
        print("         error :", resp.get("error"))
        return

    body_resp = resp.get("body", {})
    print("[CLIENT] Registo atualizado com sucesso!  ")
    print("         anon_id:", body_resp.get("anon_id"))
    print("         attrs  :", body_resp.get("attrs"))




def oams_create_sharing_registration():
    
    token = load_oas_token()
    if not token:
        return

    priv_key, pub_key_b64 = load_or_create_user_keys()
    print("=== CRIAR PARTILHA NO OAMS ===")
    print("Seção (owner):", CLIENT_SECAO)
    print("Public key (owner):", pub_key_b64)

    
    print("\n[OBSS] Índice local:")
    obss_list_local_files()
    filename = input("\nNome do ficheiro (como está no OBSS índice local): ").strip()
    if not filename:
        print("[CLIENT] Nome vazio, a cancelar.")
        return

    file_id = obss_get_local_file_id(filename)
    if not file_id:
        print("[CLIENT] Não foi possível encontrar file_id para esse ficheiro no índice local.")
        print("         Faz primeiro PUT com este cliente para teres file_id registado.")
        return

    authorized_pub_key = input("Chave pública (base64) do utilizador autorizado: ").strip()
    if not authorized_pub_key:
        print("[CLIENT] authorized_pub_key vazio, a cancelar.")
        return

    print("Permissões para o utilizador autorizado:")
    print("  1) Apenas GET (obss:get)")
    print("  2) Apenas SEARCH (obss:search)")
    print("  3) GET + SEARCH")
    perm_choice = input("> ").strip()

    if perm_choice == "1":
        permissions = ["obss:get"]
    elif perm_choice == "2":
        permissions = ["obss:search"]
    elif perm_choice == "3":
        permissions = ["obss:get", "obss:search"]
    else:
        print("[CLIENT] Opção de permissões inválida.")
        return

    body = {
        "owner_pub_key": pub_key_b64,
        "file_id": file_id,
        "authorized_pub_key": authorized_pub_key,
        "permissions": permissions,
        "extra": {},  
    }

    sig = sign_body_json_b64(priv_key, body)

    req = make_request(
        op="CreateSharingRegistration",
        body=body,
        sig=sig,
        token=token,
    )

    try:
        with connect_oams() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAMS em {OAMS_HOST}:{OAMS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAMS não respondeu ao CreateSharingRegistration.")
        return

    if resp.get("status") != "OK":
        print("[CLIENT] CreateSharingRegistration falhou.")
        print("         status:", resp.get("status"))
        print("         error :", resp.get("error"))
        print("         body  :", resp.get("body"))
        return

    body_resp = resp.get("body", {})
    print("[CLIENT] Partilha criada com sucesso!")
    print("         share_id   :", body_resp.get("share_id"))
    print("         file_id    :", body_resp.get("file_id"))
    print("         permissions:", body_resp.get("permissions"))
    print("         owner_fpr  :", body_resp.get("owner_fpr"))
    print("         auth_fpr   :", body_resp.get("authorized_fpr"))


def oams_delete_sharing_registration():
    
    token = load_oas_token()
    if not token:
        return

    priv_key, _ = load_or_create_user_keys()

    print("=== REVOGAR PARTILHA NO OAMS ===")
    share_id = input("share_id da partilha a revogar: ").strip()
    if not share_id:
        print("[CLIENT] share_id vazio.")
        return

    body = {"share_id": share_id}
    sig = sign_body_json_b64(priv_key, body)

    req = make_request(
        op="DeleteSharingRegistration",
        body=body,
        sig=sig,
        token=token,
    )

    try:
        with connect_oams() as sock:
            send_json_line(sock, req)
            resp = recv_json_line(sock)
    except ConnectionRefusedError:
        print(f"[CLIENT] Erro: não consegui ligar ao OAMS em {OAMS_HOST}:{OAMS_PORT}.")
        return

    if resp is None:
        print("[CLIENT] OAMS não respondeu ao DeleteSharingRegistration.")
        return

    if resp.get("status") != "OK":
        print("[CLIENT] DeleteSharingRegistration falhou.")
        print("         status:", resp.get("status"))
        print("         error :", resp.get("error"))
        print("         body  :", resp.get("body"))
        return

    body_resp = resp.get("body", {})
    print("[CLIENT] Partilha revogada com sucesso.")
    print("         share_id:", body_resp.get("share_id"))
    print("         status  :", body_resp.get("status"))




def main():
    print(f"[CLIENT] Seção ativa: {CLIENT_SECAO}")
    while True:
        print("\n=== CLIENT OAS/OAMS/OBSS DEMO ===")
        print("Seção :", CLIENT_SECAO)
        print("-------------------------------")
        print("1) Registar utilizador no OAS")
        print("2) Autenticar no OAS (login)")
        print("3) Ver os meus dados no OAS")
        print("4) Modificar o meu registo (email/pass)")
        print("5) Apagar o meu registo no OAS")
        print("6) Criar registo de partilha no OAMS")
        print("7) Revogar registo de partilha no OAMS")
        print("8) Upload ficheiro para OBSS (PUT)")
        print("9) Download ficheiro do OBSS (GET por nome/keyword)")
        print("10) Procurar ficheiros no OBSS (SEARCH por keyword)")
        print("0) Sair")
        choice = input("> ").strip()

        if choice == "1":
            oas_create_registration()
        elif choice == "2":
            oas_authenticate()
        elif choice == "3":
            oas_get_my_registration()
        elif choice == "4":
            oas_modify_registration()
        elif choice == "5":
            oas_delete_registration()
        elif choice == "6":
            oams_create_sharing_registration()
        elif choice == "7":
            oams_delete_sharing_registration()
        elif choice == "8":
            obss_put_file()
        elif choice == "9":
            token = load_oas_token()
            obss_get_file(auth_token=token)
        elif choice == "10":
            token = load_oas_token()
            if token:
                obss_search_files(auth_token=token)
        elif choice == "0":
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()
