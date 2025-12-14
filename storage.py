import json
from pathlib import Path

# Define paths for the data storage files
DATA_DIR = Path("data")
REG_PATH = DATA_DIR / "registration.json"
CONTACTS_PATH = DATA_DIR / "contacts.json"

def ensure_data_dir():
  # Creates the top-level data directory if it doesn't exist
  DATA_DIR.mkdir(exist_ok=True)

def read_json(path: Path, default):
  # Reads a JSON file from disk, returning default if file is missing or corrupted
  if not path.exists():
    return default
  try:
    return json.loads(path.read_text(encoding="utf-8"))
  except Exception:
    return default

def write_json(path: Path, obj):
  # Writes a Python object to a file as formatted JSON
  path.write_text(json.dumps(obj, indent=2), encoding="utf-8")