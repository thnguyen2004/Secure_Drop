import os
import hashlib
import hmac
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP

PBKDF2_ITERS = 200_000

def _b64e(b: bytes) -> str:
  return base64.b64encode(b).decode("utf-8")

def _b64d(s: str) -> bytes:
  return base64.b64decode(s.encode("utf-8"))

def hash_password(password: str) -> dict:
  salt = os.urandom(16)
  dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
  return {
    "salt": _b64e(salt),
    "hash": _b64e(dk),
    "iters": PBKDF2_ITERS
  }

def verify_password(password: str, record: dict) -> bool:
  try:
    salt = _b64d(record["salt"])
    iters = int(record.get("iters", PBKDF2_ITERS))
    expected = _b64d(record["hash"])
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(expected))
    return hmac.compare_digest(dk, expected)
  except Exception:
    return False

def sign_bytes(private_pem: str, payload: bytes) -> str:
  key = RSA.import_key(private_pem.encode("utf-8"))
  h = SHA256.new(payload)
  sig = pkcs1_15.new(key).sign(h)
  return base64.b64encode(sig).decode("utf-8")

def verify_sig(public_pem: str, payload: bytes, sig_b64: str) -> bool:
  try:
    key = RSA.import_key(public_pem.encode("utf-8"))
    h = SHA256.new(payload)
    sig = base64.b64decode(sig_b64.encode("utf-8"))
    pkcs1_15.new(key).verify(h, sig)
    return True
  except Exception:
    return False

def generate_aes_key() -> bytes:
  """Generates a random 256-bit AES key."""
  return os.urandom(32) # 256 bits

def encrypt_file(file_path: str, key: bytes) -> dict:
  """
  Encrypts a file using AES-256-GCM.
  Returns {ciphertext, nonce, tag, original_hash}.
  """
  with open(file_path, "rb") as f:
    plaintext = f.read()

  # Calculate SHA256 hash of the original file for integrity check (Milestone 5, point 1)
  original_hash = hashlib.sha256(plaintext).hexdigest()

  cipher = AES.new(key, AES.MODE_GCM)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)

  return {
    "ciphertext": _b64e(ciphertext),
    "nonce": _b64e(cipher.nonce),
    "tag": _b64e(tag),
    "original_hash": original_hash
  }

def decrypt_file(data: dict, key: bytes) -> bytes | None:
  """
  Decrypts file data and verifies the integrity tag.
  Returns the plaintext bytes, or None if decryption/integrity fails.
  """
  try:
    ciphertext = _b64d(data["ciphertext"])
    nonce = _b64d(data["nonce"])
    tag = _b64d(data["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
  except Exception:
    # Decryption or Tag verification failed (integrity check)
    return None

def wrap_aes_key(aes_key: bytes, public_pem: str) -> str:
  """Encrypts the AES key using the recipient's public key (RSA-OAEP)."""
  pub_key = RSA.import_key(public_pem.encode("utf-8"))
  cipher_rsa = PKCS1_OAEP.new(pub_key)
  wrapped_key = cipher_rsa.encrypt(aes_key)
  return _b64e(wrapped_key)

def unwrap_aes_key(wrapped_key_b64: str, private_pem: str) -> bytes | None:
  """Decrypts the AES key using the client's private key (RSA-OAEP)."""
  try:
    priv_key = RSA.import_key(private_pem.encode("utf-8"))
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    wrapped_key = _b64d(wrapped_key_b64)
    aes_key = cipher_rsa.decrypt(wrapped_key)
    return aes_key
  except Exception:
    return None

def calculate_sha256(data: bytes) -> str:
  """Calculates the SHA256 hash of raw bytes."""
  return hashlib.sha256(data).hexdigest()