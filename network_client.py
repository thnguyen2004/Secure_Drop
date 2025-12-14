import socket
import json
import os
from pathlib import Path

from network import port_for_email, id_for_email, BUFFER_SIZE
from contacts import upsert_contact_public_key, get_my_contacts
from crypto_utils import (
  sign_bytes, verify_sig, generate_aes_key, 
  encrypt_file, wrap_aes_key, calculate_sha256, _b64d 
)

# Set network timeout to allow a reasonable time for the recipient to accept
NETWORK_TIMEOUT = 15.0

def try_list_contact(my_session: dict, contact_email: str) -> dict | None:
  # Initiates the LIST1/LIST2 mutual authentication protocol
  try:
    port = port_for_email(contact_email)

    # Setup socket with a short timeout for initial check
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0) 
    sock.connect(("localhost", port))

    from_id = id_for_email(my_session["email"])
    to_id = id_for_email(contact_email)

    # Create LIST1 message and signature
    nonce = os.urandom(16).hex()
    payload = f"LIST1|{from_id}|{to_id}|{nonce}".encode("utf-8")
    sig = sign_bytes(my_session["private_key"], payload)

    msg = {
      "type": "LIST1", "from_id": from_id, "to_id": to_id, 
      "from_pub": my_session["public_key"], "nonce": nonce, "sig": sig
    }

    sock.sendall(json.dumps(msg).encode("utf-8"))
    sock.shutdown(socket.SHUT_WR) # End of sending

    # Receive LIST2 response
    data = sock.recv(BUFFER_SIZE)
    if not data:
      return None

    resp = json.loads(data.decode("utf-8"))
    
    # Check if LIST2 is accepted and verify the recipient's signature
    if resp.get("type") != "LIST2" or not resp.get("accepted"):
      return None

    peer_pub = resp.get("from_pub", "")
    peer_nonce = resp.get("nonce", "")
    peer_sig = resp.get("sig", "")
    
    payload2 = f"LIST2|{to_id}|{from_id}|{nonce}|{peer_nonce}".encode("utf-8")
    if not verify_sig(peer_pub, payload2, peer_sig):
      return None

    # Pin the recipient's public key
    upsert_contact_public_key(my_session, contact_email, peer_pub)
    
    return {"name": resp.get("name"), "email": resp.get("email")}

  except Exception:
    return None
  finally:
    try:
      sock.close()
    except:
      pass


def send_secure_file(my_session: dict, contact_email: str, file_path: str) -> bool:
  # Main function to handle the secure file transfer protocol
  file_path_obj = Path(file_path)
  
  if not file_path_obj.exists():
    print("Error: Local file not found.")
    return False

  try:
    # --- Step 0: Check Contact and Get Public Key ---
    my_contacts = get_my_contacts(my_session)
    contact_info = my_contacts.get(contact_email)
    
    if not contact_info or not contact_info.get("public_key"):
      # Key not pinned, try LIST1/LIST2 exchange first
      info = try_list_contact(my_session, contact_email)
      if not info:
        print("Error: Recipient is offline, not a mutual contact, or failed key exchange.")
        return False
      contact_info = get_my_contacts(my_session).get(contact_email) # Reload info

    recipient_pub_key = contact_info["public_key"]
    
    # --- Step 1: Prepare File and Encryption ---
    file_bytes = file_path_obj.read_bytes()
    original_hash = calculate_sha256(file_bytes)
    file_size = len(file_bytes)
    
    # Generate and wrap AES key with recipient's RSA public key
    aes_key = generate_aes_key()
    wrapped_key = wrap_aes_key(aes_key, recipient_pub_key)
    
    # Encrypt file data using AES-GCM
    enc_data = encrypt_file(file_bytes, aes_key, original_hash)
    encrypted_bytes = _b64d(enc_data["ciphertext"])
    
    # --- Step 2: Send SECURE_SEND_REQ and Wait for ACK ---
    port = port_for_email(contact_email)
    
    # Set up socket with a long timeout for user interaction
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(NETWORK_TIMEOUT)
    sock.connect(("localhost", port))
    
    from_id = id_for_email(my_session["email"])
    to_id = id_for_email(contact_email)
    sequence_num = os.urandom(16).hex() # Anti-replay sequence number

    # Create SECURE_SEND_REQ message and signature
    req_payload = f"SEND_REQ|{from_id}|{to_id}|{sequence_num}|{original_hash}".encode("utf-8")
    req_sig = sign_bytes(my_session["private_key"], req_payload)
    
    req_msg = {
      "type": "SECURE_SEND_REQ", "from_id": from_id, "to_id": to_id, 
      "from_pub": my_session["public_key"], "sequence_num": sequence_num,
      "file_name": file_path_obj.name, "file_size": file_size, 
      "original_hash": original_hash, "wrapped_key": wrapped_key,
      "nonce": enc_data["nonce"], "tag": enc_data["tag"], "sig": req_sig
    }

    # Send message and a delimiter, then the encrypted file
    json_msg_bytes = json.dumps(req_msg).encode("utf-8")
    sock.sendall(json_msg_bytes + b"\n\n")

    # Wait for SEND_ACK (Recipient approval)
    resp_data = sock.recv(BUFFER_SIZE)
    if not resp_data:
      print("Error: Recipient did not respond in time (Timeout).")
      return False
      
    resp = json.loads(resp_data.decode("utf-8").strip())

    if not resp.get("accepted"):
      print(f"Error: Transfer rejected by recipient. ({resp.get('reason', 'Unknown')})")
      return False
      
    # Verify Recipient's ACK signature
    peer_pub = resp.get("from_pub", "")
    ack_seq_num = resp.get("sequence_num", "")
    ack_sig = resp.get("sig", "")
    
    ack_payload = f"SEND_ACK|{to_id}|{from_id}|{sequence_num}|{ack_seq_num}|{original_hash}".encode("utf-8")
    
    if not verify_sig(peer_pub, ack_payload, ack_sig):
      print("Error: Recipient authentication failed during ACK.")
      return False

    print("Contact has accepted the transfer request.") # Match project output

    # --- Step 3: Send Encrypted File Chunks ---
    sock.sendall(encrypted_bytes)
    
    # --- Step 4: Receive Final Confirmation (SEND_DONE) ---
    final_resp_data = sock.recv(BUFFER_SIZE)
    if not final_resp_data:
      print("Error: Transfer completed, but did not receive final confirmation.")
      return False
      
    final_resp = json.loads(final_resp_data.decode("utf-8").strip())

    if final_resp.get("type") == "SEND_DONE" and final_resp.get("success"):
      print("File has been successfully transferred.") # Match project output
      return True
    else:
      print(f"Error: File integrity check failed on recipient side. ({final_resp.get('reason', 'Unknown')})")
      return False

  except socket.timeout:
    print("A network or protocol error occurred: timed out") # Match requested output
    return False
  except ConnectionRefusedError:
    print("A network or protocol error occurred: Connection refused (Recipient is likely offline).")
    return False
  except Exception as e:
    print(f"A network or protocol error occurred: {e}")
    return False
  finally:
    try:
      sock.close()
    except:
      pass