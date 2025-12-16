from getpass import getpass
from Crypto.PublicKey import RSA

from storage import REG_PATH, read_json, write_json
from crypto_utils import (
    hash_password, 
    verify_password,
    derive_key_from_password,
    encrypt_private_key,
    decrypt_private_key
)

def is_registered() -> bool:
  # Checks if a user registration file exists
  data = read_json(REG_PATH, default=None)
  return isinstance(data, dict) and "email" in data

def register_user():
  print("No users are registered with this client.")
  ans = input("Do you want to register a new user (y/n)? ").strip().lower()
  if ans != "y":
    return None

  # Get user information
  full_name = input("Enter Full Name: ").strip()
  email = input("Enter Email Address: ").strip()

  # Get and check password
  pw1 = getpass("Enter Password: ")
  pw2 = getpass("Re-enter Password: ")

  if pw1 != pw2:
    print("Passwords Do Not Match.")
    print("Exiting SecureDrop.")
    return None

  # 1. Hash the password (also generates salt and iteration count)
  pw_record = hash_password(pw1)

  # 2. Generate RSA Key Pair
  key = RSA.generate(2048)
  private_pem = key.export_key().decode("utf-8")
  public_pem = key.publickey().export_key().decode("utf-8")
  
  # 3. Derive symmetric key (AES-256) from the password and the new password record
  aes_key = derive_key_from_password(pw1, pw_record)
  
  # 4. Encrypt the private key using the derived AES key (AES-256-GCM)
  encrypted_private_key_data = encrypt_private_key(private_pem, aes_key)

  reg = {
    "name": full_name,
    "email": email,
    "password": pw_record,
    "public_key": public_pem,
    "private_key": encrypted_private_key_data # Store the encrypted data structure
  }

  write_json(REG_PATH, reg)
  print("Passwords Match.")
  print("User Registered.")
  print("Exiting SecureDrop.")
  return None

def login_loop() -> dict | None:
  reg = read_json(REG_PATH, default=None)
  if not reg:
    return None

  while True:
    email = input("Enter Email Address: ").strip()
    pw = getpass("Enter Password: ")

    # Scenario 2 & 3: Check email and password hash
    if email != reg.get("email") or not verify_password(pw, reg.get("password", {})):
      print("Email and Password Combination Invalid.")
      continue
    
    # 1. Password verified. Derive the symmetric key for decryption.
    aes_key = derive_key_from_password(pw, reg.get("password", {}))
    if not aes_key:
      print("Internal error during key derivation. Exiting.")
      return None

    # 2. Decrypt the private key (will fail if password/key is wrong/corrupted)
    encrypted_private_key_data = reg.get("private_key", {})
    private_pem = decrypt_private_key(encrypted_private_key_data, aes_key)

    if not private_pem:
      # Decryption/Integrity check failed
      print("Email and Password Combination Invalid.")
      continue

    # 3. Successful login
    session = {
      "name": reg["name"],
      "email": reg["email"],
      "public_key": reg["public_key"],
      "private_key": private_pem # Store the plaintext private key in the session
    }
    
    print("Login Successful.")
    return session