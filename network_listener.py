import socket
import json
import threading

from network import port_for_email, BUFFER_SIZE
from contacts import get_my_contacts

def start_listener(session: dict):
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
    print("[LISTENER] Connection accepted from", addr)

    try:
      data = b""
      while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
          break
        data += chunk

      print("[LISTENER] Raw data:", data)

      msg = json.loads(data.decode("utf-8"))
      print("[LISTENER] Parsed message:", msg)

      resp = _handle_message(session, msg)
      print("[LISTENER] Response:", resp)

      conn.sendall(json.dumps(resp).encode("utf-8"))

    except Exception as e:
      print("[LISTENER] ERROR:", repr(e))

    finally:
      conn.close()

def _handle_message(session: dict, msg: dict) -> dict:
  if msg.get("type") != "LIST_REQUEST":
    return {"type": "ERROR"}

  sender_email = msg.get("from_email")
  my_contacts = get_my_contacts(session)
  print("[LISTENER] Sender:", sender_email)
  print("[LISTENER] My contact emails:", list(my_contacts.keys()))

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
