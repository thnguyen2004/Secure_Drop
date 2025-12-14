import socket
import json
import os

from network import port_for_email, id_for_email, BUFFER_SIZE
from crypto_utils import sign_bytes, verify_sig
from contacts import upsert_contact_public_key, get_my_contacts

def try_list_contact(my_session: dict, contact_email: str) -> dict | None:
  try:
    port = port_for_email(contact_email)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect(("localhost", port))

    from_id = id_for_email(my_session["email"])
    to_id = id_for_email(contact_email)

    nonce = os.urandom(16).hex()
    payload = f"LIST1|{from_id}|{to_id}|{nonce}".encode("utf-8")
    sig = sign_bytes(my_session["private_key"], payload)

    msg = {
      "type": "LIST1",
      "from_id": from_id,
      "to_id": to_id,
      "from_pub": my_session["public_key"],
      "nonce": nonce,
      "sig": sig
    }

    sock.sendall(json.dumps(msg).encode("utf-8"))
    sock.shutdown(socket.SHUT_WR)

    data = sock.recv(BUFFER_SIZE)
    if not data:
      return None

    resp = json.loads(data.decode("utf-8"))
    if resp.get("type") != "LIST2" or not resp.get("accepted"):
      return None

    peer_pub = resp.get("from_pub", "")
    peer_nonce = resp.get("nonce", "")
    peer_sig = resp.get("sig", "")

    payload2 = f"LIST2|{to_id}|{from_id}|{nonce}|{peer_nonce}".encode("utf-8")
    if not verify_sig(peer_pub, payload2, peer_sig):
      return None

    contacts = get_my_contacts(my_session)
    pinned = contacts.get(contact_email, {}).get("public_key", "")
    if pinned and pinned != peer_pub:
      return None

    if not pinned:
      upsert_contact_public_key(my_session, contact_email, peer_pub)

    return {
      "email": contact_email,
      "name": resp.get("name", contact_email)
    }

  except Exception:
    return None
  finally:
    try:
      sock.close()
    except Exception:
      pass