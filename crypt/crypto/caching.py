from pathlib import Path
import json
import os

DATA = (
    Path(os.environ.get("APPDATA")) / "Crypt"
    if os.getenv("ENV") == "prod"
    else Path.cwd() / "data"
)
SECRET = DATA / "secrets.bin"
PUBLIC = DATA / "public_keys.json"

DATA.mkdir(parents=True, exist_ok=True)


def store_encrypted_keys(blob: bytes):
    SECRET.write_bytes(blob)


def load_encrypted_keys() -> bytes | None:
    if not SECRET.exists():
        return None
    return SECRET.read_bytes()


def store_public_keys(data: dict):
    PUBLIC.write_text(json.dumps(data))


def load_public_keys() -> dict | None:
    if not PUBLIC.exists():
        return None
    try:
        value = json.loads(PUBLIC.read_text())
        if isinstance(value, dict):
            return value
        return None
    except json.JSONDecodeError:
        return None
