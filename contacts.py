from storage import CONTACTS_PATH, read_json, write_json

def _load_contacts_root():
  return read_json(CONTACTS_PATH, default={})

def _save_contacts_root(root: dict):
  write_json(CONTACTS_PATH, root)

def add_contact(session: dict):
  full_name = input("Enter Full Name: ").strip()
  email = input("Enter Email Address: ").strip()

  root = _load_contacts_root()
  me = session["email"]

  if me not in root:
    root[me] = {
      "name": session["name"],
      "contacts": {}
    }

  root[me]["contacts"][email] = {
    "name": full_name,
    "confirmed": False,
    "public_key": ""
  }

  _save_contacts_root(root)
  print("Contact Added.")

def get_my_contacts(session: dict) -> dict:
  root = _load_contacts_root()
  me = session["email"]
  node = root.get(me, {})
  return node.get("contacts", {})

def dump_contacts_file():
  root = _load_contacts_root()
  return root
