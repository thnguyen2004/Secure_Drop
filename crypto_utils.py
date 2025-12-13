import os
import hashlib
import hmac
import base64

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