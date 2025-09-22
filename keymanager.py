import time
import base64
import json
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa

# this represents a single key entry
class KeyEntry:
    def __init__(self, kid: str, private_key, expires_at: float):
        self.kid = kid
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.expires_at = expires_at
    # this checks if a key is expired
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    # converts the key into jwk format
    def to_jwk(self) -> Dict:
        numbers = self.public_key.public_numbers()
        n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
        e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        }

# this manages multiple keys
class KeyManager:
    def __init__(self):
        self.keys: Dict[str, KeyEntry] = {}
    # generate a new key
    def generate_key(self, kid: str, ttl_seconds: int):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expires_at = time.time() + ttl_seconds
        entry = KeyEntry(kid, private_key, expires_at)
        self.keys[kid] = entry
        return entry
    # returns all unexpired keys
    def get_unexpired_keys(self):
        return [k for k in self.keys.values() if not k.is_expired()]
    # returns any single key that is unexpired
    def get_any_unexpired(self) -> Optional[KeyEntry]:
        keys = self.get_unexpired_keys()
        return keys[0] if keys else None
    # returns one expired key if there is any
    def get_expired(self) -> Optional[KeyEntry]:
        for k in self.keys.values():
            if k.is_expired():
                return k
        return None
    #  returns the jwks
    def jwks(self) -> str:
        keys = [k.to_jwk() for k in self.get_unexpired_keys()]
        return json.dumps({"keys": keys})