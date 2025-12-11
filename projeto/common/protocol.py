
import json
import socket




def send_msg(sock: socket.socket, msg: dict) -> None:
   
    data = json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(data)


def recv_msg(sock: socket.socket) -> dict | None:
    
    buf = b""
    while True:
        chunk = sock.recv(1)
        if not chunk:
            
            if not buf:
                return None
            break
        if chunk == b"\n":
            break
        buf += chunk

    if not buf:
        return None
    return json.loads(buf.decode("utf-8"))


def make_request(op, body, sig=None, token=None):
 
    return {
        "op": op,
        "body": body,
        "sig": sig,
        "token": token,
    }


def make_response(
    op: str,
    status: str = "OK",
    body: dict | None = None,
    error: str | None = None,
    sig: str | None = None,
) -> dict:

    if body is None:
        body = {}

    
    if error is ...:
        error = None
    if sig is ...:
        sig = None

    return {
        "status": status,
        "op": op,
        "body": body,
        "error": error,
        "sig": sig,
    }

