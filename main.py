from storage import ensure_data_dir
from auth import is_registered, register_user, login_loop
from shell import run_shell
from network_listener import start_listener

def main():
  ensure_data_dir()

  if not is_registered():
    register_user()
    return

  session = login_loop()
  if not session:
    return

  start_listener(session)
  run_shell(session)

if __name__ == "__main__":
  main()
