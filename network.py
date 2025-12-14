import hashlib

BASE_PORT = 5000
PORT_RANGE = 1000
BUFFER_SIZE = 4096

def port_for_email(email: str) -> int:
  # Calculates a deterministic port number based on the email hash
  digest = hashlib.sha256(email.encode("utf-8")).digest()
  value = int.from_bytes(digest[:2], "big")
  return BASE_PORT + (value % PORT_RANGE)

def id_for_email(email: str) -> str:
  # Creates a unique, consistent ID for an email (SHA256 hash)
  return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()