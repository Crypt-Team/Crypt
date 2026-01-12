import os
import json
import base64
import ulid
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b32e(b): return base64.b32encode(b).decode()
def b32d(s): return base64.b32decode(s.encode())

# ---------- KEY MANAGEMENT ----------


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


# ---------- MESSAGING ----------
from .api import get_pub


def encrypt_message(sender_keys: dict, recipient_usernames: list, body: str):
    # 1) Generate one session key
    session_key = AESGCM.generate_key(256)
    aes_msg = AESGCM(session_key)
    msg_nonce = os.urandom(12)
    message = json.dumps({"from": b32e(sender_keys["e_priv"]
                                       .public_key()
                                       .public_bytes_raw()),
                          "body": body})

    ciphertext = aes_msg.encrypt(msg_nonce, message.encode(), None)
    # 2) Encrypt session key for each recipient
    key_blocks = []
    for username in recipient_usernames:
        rx_pub, _ = get_pub(username)
        rx = x25519.X25519PublicKey.from_public_bytes(rx_pub)

        eph = x25519.X25519PrivateKey.generate()
        shared = eph.exchange(rx)

        kek = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"crypt-msg"
        ).derive(shared)

        aes_k = AESGCM(kek)
        k_nonce = os.urandom(12)
        wrapped = aes_k.encrypt(k_nonce, session_key, None)

        key_blocks.append(
            b32e(
                eph.public_key().public_bytes_raw() +
                k_nonce +
                wrapped
            )
        )

    # 3) Sign plaintext ONCE
    sig = sender_keys["e_priv"].sign(body.encode())

    # 4) Assemble final message
    return "$$" + "$$".join([
        b32e(ulid.new().bytes),
        "$".join(key_blocks),
        b32e(msg_nonce + ciphertext),
        b32e(sig)
    ]) + "$$"


def decrypt_message(recipient_keys: dict, payload: str):
    _, T, keys_blob, C_blob, sig_blob, _ = payload.split("$$")

    cipher_data = b32d(C_blob)
    msg_nonce = cipher_data[:12]
    ciphertext = cipher_data[12:]

    key_blocks = keys_blob.split("$")

    for block in key_blocks:
        try:
            data = b32d(block)
            eph_pub = x25519.X25519PublicKey.from_public_bytes(data[:32])
            k_nonce = data[32:44]
            wrapped = data[44:]

            shared = recipient_keys["x_priv"].exchange(eph_pub)
            kek = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"crypt-msg"
            ).derive(shared)

            session_key = AESGCM(kek).decrypt(k_nonce, wrapped, None)

            msg = AESGCM(session_key).decrypt(
                msg_nonce,
                ciphertext,
                None
            )

            message = json.loads(msg.decode())

            # Verify signature
            ed25519.Ed25519PublicKey.from_public_bytes(b32d(message["from"]))\
                .verify(b32d(sig_blob), message["body"].encode())

            return {"timestamp": T, "message": message["body"]}

        except Exception:
            continue

    raise ValueError("Message not intended for this recipient")


"""
signup("alice", "a@a.com", "password123")
signup("bob", "b@b.com", "hunter2")

alice = login("alice", "password123")
bob = login("bob", "hunter2")

msg = encrypt_message(alice, ["bob"], "Hello Bob")
print(msg)

print(decrypt_message(bob, msg))
"""
