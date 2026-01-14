import os
import json
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b32e(b): return base64.b32encode(b).decode()
def b32d(s): return base64.b32decode(s.encode())


def generate_keys():
    return {
        "x_priv": x25519.X25519PrivateKey.generate(),
        "e_priv": ed25519.Ed25519PrivateKey.generate()
    }


def wrap_keys(keys, password):
    salt = os.urandom(16)
    k = hash_secret_raw(
        password.encode(), salt,
        time_cost=3, memory_cost=2**17,
        parallelism=1, hash_len=32,
        type=Type.ID
    )
    aes = AESGCM(k)
    nonce = os.urandom(12)

    blob = json.dumps({
        "x": b32e(keys["x_priv"].private_bytes_raw()),
        "e": b32e(keys["e_priv"].private_bytes_raw())
    }).encode()

    ct = aes.encrypt(nonce, blob, None)
    return b32e(salt + nonce + ct)


def unwrap_keys(blob, password):
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]

    k = hash_secret_raw(
        password.encode(), salt,
        time_cost=3, memory_cost=2**17,
        parallelism=1, hash_len=32,
        type=Type.ID
    )
    aes = AESGCM(k)
    data = json.loads(aes.decrypt(nonce, ct, None))

    return {
        "x_priv": x25519.X25519PrivateKey.from_private_bytes(b32d(data["x"])),
        "e_priv": ed25519.Ed25519PrivateKey.from_private_bytes(b32d(data["e"]))
    }
