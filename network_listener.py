import socket
import json

from network import port_for_email, id_for_email, BUFFER_SIZE
from contacts import get_my_contacts, upsert_contact_public_key
from crypto_utils import verify_sig, sign_bytes

def start_listener(session: dict):
  import threading
  t = threading.Thread(target=_listener_loop, args=(session,), daemon=True)
  t.start()

def _listener_loop(session: dict):
  port = port_for_email(session["email"])
  print(f"[LISTENER] Starting listener for {session['email']} on port {port}")

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind(("", port))
  sock.listen(5)

  print(f"[LISTENER] Listening on port {port}")

  while True:
    conn, addr = sock.accept()
    try:
      data = b""
      while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
          break
        data += chunk

      if not data:
        continue

      msg = json.loads(data.decode("utf-8"))
      resp = _handle_message(session, msg)
      conn.sendall(json.dumps(resp).encode("utf-8"))

    except Exception:
      pass
    finally:
      conn.close()

def _handle_message(session: dict, msg: dict) -> dict:
  if msg.get("type") != "LIST1":
    return {"type": "ERROR"}

  me_email = session["email"]
  me_id = id_for_email(me_email)

  from_id = msg.get("from_id", "")
  to_id = msg.get("to_id", "")
  from_pub = msg.get("from_pub", "")
  nonce = msg.get("nonce", "")
  sig = msg.get("sig", "")

  if to_id != me_id:
    return {"type": "LIST2", "accepted": False}

  payload = f"LIST1|{from_id}|{to_id}|{nonce}".encode("utf-8")
  if not verify_sig(from_pub, payload, sig):
    return {"type": "LIST2", "accepted": False}

  my_contacts = get_my_contacts(session)

  sender_email = None
  for email in my_contacts.keys():
    if id_for_email(email) == from_id:
      sender_email = email
      break

  if not sender_email:
    return {"type": "LIST2", "accepted": False}

  pinned = my_contacts.get(sender_email, {}).get("public_key", "")
  if pinned and pinned != from_pub:
    return {"type": "LIST2", "accepted": False}

  if not pinned:
    upsert_contact_public_key(session, sender_email, from_pub)

  my_nonce = nonce
  peer_nonce = "srv_" + nonce

  payload2 = f"LIST2|{to_id}|{from_id}|{my_nonce}|{peer_nonce}".encode("utf-8")
  sig2 = sign_bytes(session["private_key"], payload2)

  return {
    "type": "LIST2",
    "accepted": True,
    "name": session["name"],
    "from_pub": session["public_key"],
    "nonce": peer_nonce,
    "sig": sig2
  }