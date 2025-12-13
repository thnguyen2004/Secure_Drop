import socket
import json
import threading

from network import LISTEN_PORT, BUFFER_SIZE
from contacts import get_my_contacts

def start_listener(session: dict):
  t = threading.Thread(target=_listener_loop, args=(session,), daemon=True)
  t.start()

def _listener_loop(session: dict):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind(("", LISTEN_PORT))
  sock.listen(5)

  while True:
    conn, addr = sock.accept()
    try:
      data = conn.recv(BUFFER_SIZE)
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
  if msg.get("type") != "LIST_REQUEST":
    return {"type": "ERROR"}

  sender_email = msg.get("from_email")
  my_contacts = get_my_contacts(session)

  # Reciprocity check
  if sender_email in my_contacts:
    return {
      "type": "LIST_RESPONSE",
      "accepted": True,
      "email": session["email"],
      "name": session["name"]
    }

  return {
    "type": "LIST_RESPONSE",
    "accepted": False
  }
