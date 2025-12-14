from contacts import add_contact, get_my_contacts
from network_client import try_list_contact, send_secure_file 

def run_shell(session: dict):
  # Main loop for the SecureDrop command line interface
  while True:
    cmdline = input("secure_drop> ").strip()

    if cmdline == "":
      continue

    if cmdline == "help":
      # Match the exact format from the PDF
      print("\"add\"-> Add a new contact")
      print("\"list\"-> List all online contacts")
      print("\"send\"-> Transfer file to contact")
      print("\"exit\"-> Exit SecureDrop")
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
        print("Usage: send <contact_email> <local_file_path>")
        continue
      
      recipient_email = parts[1]
      local_file_path = parts[2]
      
      send_secure_file(session, recipient_email, local_file_path)
      continue

    if cmdline == "exit":
      return

    # Handle unknown commands gracefully
    print('Unknown command. Type "help" for commands.')


def handle_list(session: dict):
  # Lists contacts that are online and mutually authenticated
  contacts = get_my_contacts(session)
  online = []

  for email in contacts:
    # Perform LIST1/LIST2 exchange to check if they are online
    info = try_list_contact(session, email)
    if info:
      online.append(info)

  if not online:
    print("No contacts online.")
    return

  print("The following contacts are online:")
  for c in online:
    # Match the exact PDF output format: "* Bob"
    print(f'* {c["name"]}')