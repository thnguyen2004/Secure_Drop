import os
import hashlib
import hmac
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP

PBKDF2_ITERS = 200_000 # Standard iteration count for password hashing

# Base64 encoding/decoding utilities
def _b64e(b: bytes) -> str:
  return base64.b64encode(b).decode("utf-8")

def _b64d(s: str) -> bytes:
  return base64.b64decode(s.encode("utf-8"))

def calculate_sha256(data: bytes) -> str:
  # Calculates the SHA256 hash of a file's content
  return hashlib.sha256(data).hexdigest()

def hash_password(password: str) -> dict:
  # Hashes a password using PBKDF2-HMAC-SHA256 with a random salt
  salt = os.urandom(16)
  dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
  return {
    "salt": _b64e(salt),
    "hash": _b64e(dk),
    "iters": PBKDF2_ITERS
  }

def verify_password(password: str, record: dict) -> bool:
  # Verifies a password against the stored hash record
  try:
    salt = _b64d(record["salt"])
    iters = int(record.get("iters", PBKDF2_ITERS))
    expected = _b64d(record["hash"])
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(expected))
    return hmac.compare_digest(dk, expected)
  except Exception:
    return False

def sign_bytes(private_pem: str, data: bytes) -> str:
  # Signs bytes using the private key (for non-repudiation)
  private_key = RSA.import_key(private_pem.encode("utf-8"))
  h = SHA256.new(data)
  signature = pkcs1_15.new(private_key).sign(h)
  return _b64e(signature)

def verify_sig(public_pem: str, data: bytes, sig_b64: str) -> bool:
  # Verifies a signature using the public key
  try:
    public_key = RSA.import_key(public_pem.encode("utf-8"))
    sig = _b64d(sig_b64)
    h = SHA256.new(data)
    pkcs1_15.new(public_key).verify(h, sig)
    return True
  except Exception:
    return False

def generate_aes_key() -> bytes:
  # Generates a random 256-bit AES key
  return os.urandom(32)

def encrypt_file(plaintext_bytes: bytes, key: bytes, original_hash: str) -> dict:
  # Encrypts file data using AES-256-GCM (provides confidentiality and integrity)
  cipher = AES.new(key, AES.MODE_GCM)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
  return {
    "ciphertext": _b64e(ciphertext),
    "nonce": _b64e(cipher.nonce),
    "tag": _b64e(tag),
    "original_hash": original_hash
  }

def decrypt_file(data: dict, key: bytes) -> bytes | None:
  # Decrypts file data and verifies the GCM tag for integrity
  try:
    ciphertext = _b64d(data["ciphertext"])
    nonce = _b64d(data["nonce"])
    tag = _b64d(data["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
  except Exception:
    return None 

def wrap_aes_key(aes_key: bytes, public_pem: str) -> str:
  # Encrypts the symmetric AES key using the recipient's RSA public key (OAEP)
  pub_key = RSA.import_key(public_pem.encode("utf-8"))
  cipher_rsa = PKCS1_OAEP.new(pub_key)
  wrapped_key = cipher_rsa.encrypt(aes_key)
  return _b64e(wrapped_key)

def unwrap_aes_key(wrapped_key_b64: str, private_pem: str) -> bytes | None:
  # Decrypts the symmetric AES key using the client's RSA private key (OAEP)
  try:
    private_key = RSA.import_key(private_pem.encode("utf-8"))
    cipher_rsa = PKCS1_OAEP.new(private_key)
    wrapped_key = _b64d(wrapped_key_b64)
    aes_key = cipher_rsa.decrypt(wrapped_key)
    return aes_key
  except Exception:
    return None