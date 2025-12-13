from contacts import add_contact, get_my_contacts
from network_client import try_list_contact

def run_shell(session: dict):
  while True:
    cmdline = input("secure_drop> ").strip()

    if cmdline == "":
      continue

    if cmdline == "help":
      print('"add" -> Add a new contact')
      print('"list" -> List all online contacts')
      print('"send" -> Transfer file to contact')
      print('"exit" -> Exit SecureDrop')
      continue

    if cmdline == "add":
      add_contact(session)
      continue

    if cmdline == "list":
        handle_list(session)
        continue

    if cmdline.startswith("send"):
      # Milestone 5 replaces this with actual transfer logic
      print("Send is not implemented yet.")
      continue

    if cmdline == "exit":
      return

    # Incorrect command should not crash or exit (scenario #6)
    print('Unknown command. Type "help" for commands.')


def handle_list(session: dict):
  contacts = get_my_contacts(session)
  online = []

  for email in contacts:
    info = try_list_contact(session, email)
    if info:
      online.append(info)

  if not online:
    print("No contacts online.")
    return

  print("The following contacts are online:")
  for c in online:
    print(f'* {c["name"]} <{c["email"]}>')