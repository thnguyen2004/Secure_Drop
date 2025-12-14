from storage import CONTACTS_PATH, read_json, write_json

def _load_contacts_root():
  # Loads the entire contacts file structure
  return read_json(CONTACTS_PATH, default={})

def _save_contacts_root(root: dict):
  # Saves the entire contacts file structure
  write_json(CONTACTS_PATH, root)

def add_contact(session: dict):
  # Prompts user and adds a new contact to their list
  full_name = input("Enter Full Name: ").strip()
  email = input("Enter Email Address: ").strip()

  root = _load_contacts_root()
  me = session["email"]

  # Ensure the user's entry exists in the contact file
  if me not in root:
    root[me] = {
      "name": session["name"],
      "contacts": {}
    }

  # Add or overwrite the contact details
  root[me]["contacts"][email] = {
    "name": full_name,
    "confirmed": False,
    "public_key": ""
  }

  _save_contacts_root(root)
  print("Contact Added.")

def get_my_contacts(session: dict) -> dict:
  # Returns the current user's personal contact dictionary
  root = _load_contacts_root()
  me = session["email"]
  node = root.get(me, {})
  return node.get("contacts", {})

def upsert_contact_public_key(session: dict, email: str, public_key: str):
  # Saves or updates the public key for a contact (pinning)
  root = _load_contacts_root()
  me = session["email"]

  if me not in root or email not in root[me].get("contacts", {}):
    return

  root[me]["contacts"][email]["public_key"] = public_key
  
  _save_contacts_root(root)