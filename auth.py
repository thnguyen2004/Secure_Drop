from getpass import getpass
from Crypto.PublicKey import RSA

from storage import REG_PATH, read_json, write_json
from crypto_utils import hash_password, verify_password

def is_registered() -> bool:
  data = read_json(REG_PATH, default=None)
  return isinstance(data, dict) and "email" in data

def register_user():
  print("No users are registered with this client.")
  ans = input("Do you want to register a new user (y/n)? ").strip().lower()
  if ans != "y":
    return None

  full_name = input("Enter Full Name: ").strip()
  email = input("Enter Email Address: ").strip()

  pw1 = getpass("Enter Password: ")
  pw2 = getpass("Re-enter Password: ")

  if pw1 != pw2:
    print("Passwords Do Not Match.")
    print("Exiting SecureDrop.")
    return None

  pw_record = hash_password(pw1)

  key = RSA.generate(2048)
  private_pem = key.export_key().decode("utf-8")
  public_pem = key.publickey().export_key().decode("utf-8")

  reg = {
    "name": full_name,
    "email": email,
    "password": pw_record,
    "public_key": public_pem,
    "private_key": private_pem
  }

  write_json(REG_PATH, reg)
  print("Passwords Match.")
  print("User Registered.")
  print("Exiting SecureDrop.")
  return None

def login_loop():
  reg = read_json(REG_PATH, default=None)
  if not reg:
    return None

  while True:
    email = input("Enter Email Address: ").strip()
    pw = getpass("Enter Password: ")

    if email != reg.get("email") or not verify_password(pw, reg.get("password", {})):
      print("Email and Password Combination Invalid.")
      continue

    session = {
      "name": reg["name"],
      "email": reg["email"],
      "public_key": reg["public_key"],
      "private_key": reg["private_key"]
    }
    print("Welcome to SecureDrop.")
    print('Type "help" For Commands.')
    return session