import socket
import json
import os
import math
from pathlib import Path

from network import port_for_email, id_for_email, BUFFER_SIZE
from crypto_utils import sign_bytes, verify_sig
from contacts import upsert_contact_public_key, get_my_contacts
from crypto_utils import (
  sign_bytes, verify_sig, generate_aes_key, 
  encrypt_file, wrap_aes_key, _b64e, _b64d 
)

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

def send_secure_file(my_session: dict, recipient_email: str, file_path: str) -> bool:
  file_path_obj = Path(file_path)
  
  if not file_path_obj.exists() or not file_path_obj.is_file():
    print(f"Error: File not found or is not a file: {file_path}")
    return False

  contacts = get_my_contacts(my_session)
  contact = contacts.get(recipient_email)
  
  if not contact or not contact.get("public_key"):
    # Scenarios 8 & 9: UD is not a contact, UC is a contact but maybe not mutual/online, 
    # but the primary failure is the missing public_key from a mutual connection.
    print(f"Error: Could not find verified public key for contact {recipient_email}. Please 'list' first.")
    # The program should not crash or exit (Milestone 5, Scenario 8 & 9)
    return False

  # --- File Encryption and Key Wrapping ---
  try:
    aes_key = generate_aes_key()
    encrypted_data = encrypt_file(file_path, aes_key)
    wrapped_key = wrap_aes_key(aes_key, contact["public_key"])
  except Exception as e:
    print(f"Error during encryption or key wrapping: {e}")
    return False

  original_hash = encrypted_data["original_hash"]
  encrypted_bytes = _b64d(encrypted_data["ciphertext"])
  file_size = len(encrypted_bytes)
  
  # --- Step 1: Send Request (Secure Protocol) ---
  try:
    port = port_for_email(recipient_email)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)
    sock.connect(("localhost", port))

    from_id = id_for_email(my_session["email"])
    to_id = id_for_email(recipient_email)
    
    # Anti-replay: Use a random seed/sequence number (Milestone 5, point 2)
    sequence_num = os.urandom(16).hex() 
    
    # Payload for signature (non-repudiation)
    req_payload = f"SEND_REQ|{from_id}|{to_id}|{sequence_num}|{original_hash}".encode("utf-8")
    req_sig = sign_bytes(my_session["private_key"], req_payload)

    req_msg = {
      "type": "SECURE_SEND_REQ",
      "from_id": from_id,
      "to_id": to_id,
      "from_pub": my_session["public_key"],
      "sequence_num": sequence_num,
      "file_name": file_path_obj.name,
      "file_size": file_size,
      "original_hash": original_hash,
      "wrapped_key": wrapped_key,
      "nonce": encrypted_data["nonce"], # AES nonce
      "tag": encrypted_data["tag"],     # AES tag
      "sig": req_sig
    }

    sock.sendall(json.dumps(req_msg).encode("utf-8") + b"\n\n") 
    
    # --- Step 2: Receive Acceptance/Rejection ---
    resp_data = sock.recv(BUFFER_SIZE)
    if not resp_data:
      print("Error: Recipient did not respond to the transfer request.")
      return False
      
    resp = json.loads(resp_data.decode("utf-8").strip())
    
    if resp.get("type") != "SEND_ACK" or not resp.get("accepted"):
      print(f"Transfer failed. Recipient rejected or is not online/mutual. (Error: {resp.get('reason', 'Unknown')})")
      return False
      
    print("Contact has accepted the transfer request.") # Project example output
    
    # Verify Recipient's ACK signature
    peer_pub = resp.get("from_pub", "")
    ack_seq_num = resp.get("sequence_num", "")
    ack_sig = resp.get("sig", "")
    
    ack_payload = f"SEND_ACK|{to_id}|{from_id}|{sequence_num}|{ack_seq_num}|{original_hash}".encode("utf-8")
    
    if not verify_sig(peer_pub, ack_payload, ack_sig):
      print("Error: Recipient authentication failed during ACK.")
      return False

    # --- Step 3: Send Encrypted File Chunks ---
    print(f"Sending {file_path_obj.name} ({math.ceil(file_size/1024)} KB)...")
    
    # Send the encrypted file data
    sock.sendall(encrypted_bytes)
    
    # --- Step 4: Receive Final Confirmation ---
    final_resp_data = sock.recv(BUFFER_SIZE)
    if not final_resp_data:
      print("Error: Transfer completed, but did not receive final confirmation.")
      return False
      
    final_resp = json.loads(final_resp_data.decode("utf-8").strip())

    if final_resp.get("type") == "SEND_DONE" and final_resp.get("success"):
      print("File has been successfully transferred.") # Project example output
      return True
    else:
      print(f"Error: File transfer failed integrity check on recipient side. ({final_resp.get('reason', 'Unknown')})")
      return False

  except Exception as e:
    print(f"A network or protocol error occurred: {e}")
    # The program should not crash or exit (Milestone 5, Scenario 8 & 9)
    return False
  finally:
    try:
      sock.close()
    except Exception:
      pass