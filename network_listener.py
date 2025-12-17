import socket
import json
import threading
import os
import time
from pathlib import Path

from network import port_for_email, id_for_email, BUFFER_SIZE
from contacts import get_my_contacts, upsert_contact_public_key
from crypto_utils import (
    verify_sig, sign_bytes, unwrap_aes_key, 
    decrypt_file, calculate_sha256, _b64d, _b64e
)

def start_listener(session: dict):
  # Starts the listener in a background thread
  t = threading.Thread(target=_listener_loop, args=(session,), daemon=True)
  t.start()

def _listener_loop(session: dict):
  # The main loop that accepts network connections
  port = port_for_email(session["email"])

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  try:
    sock.bind(("", port))
  except OSError:
    print(f"[ERROR] Could not bind to port {port}. Is another instance running?")
    return
    
  sock.listen(5)

  while True:
    conn, _ = sock.accept()
    try:
      # Read message, looking for the \n\n delimiter for file data
      data = b""
      while b"\n\n" not in data and len(data) < BUFFER_SIZE * 3: 
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
          break
        data += chunk

      if not data:
        continue

      # Separate JSON message from file data preamble
      try:
        msg_json, file_data_preamble = data.split(b"\n\n", 1)
        msg = json.loads(msg_json.decode("utf-8"))
      except ValueError:
        # No delimiter means it's a simple request (like LIST1)
        msg = json.loads(data.decode("utf-8").strip())
        file_data_preamble = b""
      except json.JSONDecodeError:
        continue

      # Handle the message type
      if msg.get("type") == "LIST1":
        resp = _handle_list1(session, msg)
        conn.sendall(json.dumps(resp).encode("utf-8"))
      
      elif msg.get("type") == "SECURE_SEND_REQ":
        _handle_secure_send_req(session, msg, conn, file_data_preamble)
        
    except Exception:
      pass
    finally:
      conn.close()

def _handle_list1(session: dict, msg: dict) -> dict:
  # Handles the LIST1 request and mutual authentication
  me_id = id_for_email(session["email"])

  from_id = msg.get("from_id", "")
  to_id = msg.get("to_id", "")
  from_pub = msg.get("from_pub", "")
  nonce = msg.get("nonce", "")
  sig = msg.get("sig", "")

  if to_id != me_id:
    return {"type": "LIST2", "accepted": False}

  # 1. Verify LIST1 Signature
  payload = f"LIST1|{from_id}|{to_id}|{nonce}".encode("utf-8")
  if not verify_sig(from_pub, payload, sig):
    return {"type": "LIST2", "accepted": False}

  my_contacts = get_my_contacts(session)

  # 2. Check if Sender is in Recipient's Contacts
  sender_email = None
  for email in my_contacts.keys():
    if id_for_email(email) == from_id:
      sender_email = email
      break

  if not sender_email:
    return {"type": "LIST2", "accepted": False}

  # 3. Check for Public Key Pinning/Integrity
  pinned = my_contacts.get(sender_email, {}).get("public_key", "")
  if pinned and pinned != from_pub:
    return {"type": "LIST2", "accepted": False}

  if not pinned:
    # Pin the key for the first time
    upsert_contact_public_key(session, sender_email, from_pub)

  # 4. Generate LIST2 Response
  my_nonce = nonce
  peer_nonce = "srv_" + nonce 

  payload2 = f"LIST2|{me_id}|{from_id}|{my_nonce}|{peer_nonce}".encode("utf-8")
  sig2 = sign_bytes(session["private_key"], payload2)

  return {
    "type": "LIST2", "accepted": True, "name": session["name"],
    "from_pub": session["public_key"], "nonce": peer_nonce,
    "sig": sig2, "email": session["email"]
  }


def _handle_secure_send_req(session: dict, req_msg: dict, conn: socket.socket, data: bytes):
  # Handles the incoming SECURE_SEND_REQ and file transfer
  me_id = id_for_email(session["email"])

  # Extract request data
  from_id = req_msg.get("from_id", "")
  to_id = req_msg.get("to_id", "")
  from_pub = req_msg.get("from_pub", "")
  seq_num = req_msg.get("sequence_num", "")
  file_name = req_msg.get("file_name", "received_file")
  file_size = req_msg.get("file_size", 0)
  original_hash = req_msg.get("original_hash", "")
  wrapped_key = req_msg.get("wrapped_key", "")
  aes_nonce_b64 = req_msg.get("nonce", "")
  aes_tag_b64 = req_msg.get("tag", "")
  req_sig = req_msg.get("sig", "")
  
  if to_id != me_id:
    conn.sendall(json.dumps({"type": "SEND_ACK", "accepted": False, "reason": "Wrong recipient"}).encode("utf-8"))
    return

  # 1. Mutual Contact/Authentication Check (Scenario 9)
  my_contacts = get_my_contacts(session)
  sender_email = None
  sender_name = "Unknown Contact" 
  
  for email, info in my_contacts.items():
    if id_for_email(email) == from_id and info.get("public_key") == from_pub:
      sender_email = email
      sender_name = info.get("name", sender_email) 
      break

  if not sender_email:
    conn.sendall(json.dumps({"type": "SEND_ACK", "accepted": False, "reason": "Not a recognized mutual contact."}).encode("utf-8"))
    return
    
  # 2. Verify Sender's Request Signature
  req_payload = f"SEND_REQ|{from_id}|{to_id}|{seq_num}|{original_hash}".encode("utf-8")
  if not verify_sig(from_pub, req_payload, req_sig):
    conn.sendall(json.dumps({"type": "SEND_ACK", "accepted": False, "reason": "Sender signature verification failed."}).encode("utf-8"))
    return

  # 3. User Approval
  print(f"\nContact '{sender_name} <{sender_email}>' is sending a file. Press Enter.")
  ans = input("> Accept (y/n)? ").strip().lower() 
  
  if ans != "y":
    conn.sendall(json.dumps({"type": "SEND_ACK", "accepted": False, "reason": "Transfer rejected by user."}).encode("utf-8"))
    return

  # 4. Send ACK Response (Anti-Replay)
  ack_seq_num = os.urandom(16).hex()
  ack_payload = f"SEND_ACK|{me_id}|{from_id}|{seq_num}|{ack_seq_num}|{original_hash}".encode("utf-8")
  ack_sig = sign_bytes(session["private_key"], ack_payload)
  
  ack_msg = {
    "type": "SEND_ACK", "accepted": True, "from_pub": session["public_key"],
    "sequence_num": ack_seq_num, "sig": ack_sig
  }
  
  conn.sendall(json.dumps(ack_msg).encode("utf-8"))
  
  # 5. Receive File Chunks
  try:
    encrypted_data_chunks = [data] # Start with any preamble data
    bytes_recd = len(data)
    
    conn.settimeout(10.0) # Set a timeout for file reception
    while bytes_recd < file_size:
      chunk = conn.recv(BUFFER_SIZE)
      if not chunk:
        raise Exception("Client closed connection prematurely.")
      encrypted_data_chunks.append(chunk)
      bytes_recd += len(chunk)

    encrypted_file_bytes = b"".join(encrypted_data_chunks)[:file_size] 
    
    if len(encrypted_file_bytes) != file_size:
      raise Exception("File size mismatch.")
      
  except Exception as e:
    conn.sendall(json.dumps({"type": "SEND_DONE", "success": False, "reason": f"Network error: {e}"}).encode("utf-8"))
    return

  # 6. Decrypt and Integrity Check
  try:
    # Unwrap AES Key
    aes_key = unwrap_aes_key(wrapped_key, session["private_key"])
    if not aes_key:
      raise Exception("Failed to unwrap AES key.")
      
    # Prepare data for decryption
    decrypt_data = {
      "ciphertext": _b64e(encrypted_file_bytes), "nonce": aes_nonce_b64, "tag": aes_tag_b64
    }
    
    # Decrypt file (AES-GCM verifies the tag)
    plaintext_bytes = decrypt_file(decrypt_data, aes_key)
    if plaintext_bytes is None:
      raise Exception("Integrity check failed (Bad GCM Tag).")
      
    # Verify SHA256 Hash of Decrypted Content
    calculated_hash = calculate_sha256(plaintext_bytes)
    if calculated_hash != original_hash:
      raise Exception("Decrypted file hash mismatch.")

    # 7. Save File
    output_path = Path("received") / file_name
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_bytes(plaintext_bytes)
    
    # 8. Send DONE Confirmation
    conn.sendall(json.dumps({"type": "SEND_DONE", "success": True}).encode("utf-8"))

  except Exception as e:
    conn.sendall(json.dumps({"type": "SEND_DONE", "success": False, "reason": f"Integrity/Decryption Failed: {e}"}).encode("utf-8"))