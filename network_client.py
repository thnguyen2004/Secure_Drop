import socket
import json
from network import port_for_email, BUFFER_SIZE

def try_list_contact(my_session: dict, contact_email: str) -> dict | None:
  """
  Returns contact info dict if reciprocal + online, else None
  """
  try:
    # In this project, hostname == email mapping is assumed via container DNS
    port = port_for_email(contact_email)
    print(f"[CLIENT] Attempting {contact_email} on localhost:{port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    sock.connect(("localhost", port))

    msg = {
      "type": "LIST_REQUEST",
      "from_email": my_session["email"],
      "from_name": my_session["name"]
    }

    sock.sendall(json.dumps(msg).encode("utf-8"))
    sock.shutdown(socket.SHUT_WR)
    data = sock.recv(BUFFER_SIZE)

    resp = json.loads(data.decode("utf-8"))

    if resp.get("type") == "LIST_RESPONSE" and resp.get("accepted"):
      return {
        "email": resp["email"],
        "name": resp["name"]
      }

  except Exception:
    pass
  finally:
    try:
      sock.close()
    except Exception:
      pass

  return None
