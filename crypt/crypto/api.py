import base64
import requests
import logging
from ..crypto import generate_keys, wrap_keys, unwrap_keys
from ..crypto.caching import load_encrypted_keys, store_encrypted_keys, \
    load_public_keys, store_public_keys

logger = logging.getLogger("crypt.crypto.api")

API = "https://users.crypt-api.workers.dev"


def b32e(b): return base64.b32encode(b).decode()
def b32d(s): return base64.b32decode(s.encode())


def signup(username, email, password):
    keys = generate_keys()
    wrapped = wrap_keys(keys, password)

    r = requests.post(API + "/signup", json={
        "username": username,
        "email": email,
        "password": password,
        "wrapped_keys": wrapped,
        "x25519_pub": b32e(keys["x_priv"].public_key().public_bytes_raw()),
        "ed25519_pub": b32e(keys["e_priv"].public_key().public_bytes_raw())
    })
    if r.status_code == 409:
        return f"User {username} already exists"
    else:
        r.raise_for_status()
        return "Signup successful"


def login(username, password):
    if (keys := load_encrypted_keys()):
        return unwrap_keys(keys, password)
    r = requests.post(API + "/login", json={
        "username": username,
        "password": password
    }).json()
    if r == {"error": "Invalid login"}:
        raise ValueError("Invalid username or password")
    wrapped_keys = b32d(r["wrapped_keys"])
    store_encrypted_keys(wrapped_keys)
    return unwrap_keys(wrapped_keys, password)


def get_pub(username):
    logger.debug(f"Fetching public keys for {username}")
    if (pub := load_public_keys()):
        if username in pub:
            return (
                b32d(pub[username]["x25519_pub"]),
                b32d(pub[username]["ed25519_pub"])
            )
    try:
        r = requests.get(API + f"/pub/{username}")
        r.raise_for_status()
    except requests.HTTPError as e:
        if r.status_code == 404:
            raise ValueError(f"User '{username}' not found")
        logger.error(f"Failed to fetch public keys for {username}: {e}")
        raise
    rjson = r.json()
    store_public_keys({username: rjson})
    return (
        b32d(rjson["x25519_pub"]),
        b32d(rjson["ed25519_pub"])
    )
