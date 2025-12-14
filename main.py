from storage import ensure_data_dir
from auth import is_registered, register_user, login_loop
from shell import run_shell
from network_listener import start_listener

def main():
  # Ensure the data directory exists
  ensure_data_dir()

  # Handle initial user registration if no user exists
  if not is_registered():
    register_user()
    return

  # Handle user login loop
  session = login_loop()
  if not session:
    return

  # Start the background listener for incoming connections
  start_listener(session)
  
  # Start the main interactive shell
  run_shell(session)

if __name__ == "__main__":
  main()