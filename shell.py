from contacts import add_contact, get_my_contacts
from network_client import try_list_contact, send_secure_file # Import the new transfer function

def run_shell(session: dict):
  while True:
    cmdline = input("secure_drop> ").strip()

    if cmdline == "":
      continue

    if cmdline == "help":
      print('\"add\" -> Add a new contact')
      print('\"list\" -> List all online contacts')
      print('\"send\" -> Transfer file to contact')
      print('\"exit\" -> Exit SecureDrop')
      continue

    if cmdline == "add":
      add_contact(session)
      continue

    if cmdline == "list":
        handle_list(session)
        continue

    if cmdline.startswith("send"):
      parts = cmdline.split()
      if len(parts) != 3:
        # Scenario 8 & 9 are handled within send_secure_file logic
        print("Usage: send <contact_email> <local_file_path>")
        continue
      
      recipient_email = parts[1]
      local_file_path = parts[2]
      
      # Call the Milestone 5 transfer function
      send_secure_file(session, recipient_email, local_file_path)
      continue

    if cmdline == "exit":
      return

    # Incorrect command should not crash or exit (scenario #6)
    print('Unknown command. Type \"help\" for commands.')


def handle_list(session: dict):
  contacts = get_my_contacts(session)
  online = []

  for email in contacts:
    # try_list_contact handles the LIST1/LIST2 protocol for mutual authentication
    info = try_list_contact(session, email)
    if info:
      online.append(info)

  if not online:
    print("No contacts online.")
    return

  print("The following contacts are online:")
  for c in online:
    print(f'* {c["name"]} <{c["email"]}>')