"""Independently compute MySQL authentication test vectors for crates/dbtap-replay/src/myclient.rs."""
import hashlib

pw = b"secret"
nonce = bytes(range(1, 21))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


h1 = hashlib.sha1(pw).digest()
print("native", xor(h1, hashlib.sha1(nonce + hashlib.sha1(h1).digest()).digest()).hex())
h1 = hashlib.sha256(pw).digest()
print("sha2  ", xor(h1, hashlib.sha256(hashlib.sha256(h1).digest() + nonce).digest()).hex())
