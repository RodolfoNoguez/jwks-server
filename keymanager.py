import time
import base64
import json
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyEntry:
    def __init__(self, kid: str, private_key, expires_at: float):
        self.kid = kid
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

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


class KeyManager:
    def __init__(self):
        self.keys: Dict[str, KeyEntry] = {}

    def generate_key(self, kid: str, ttl_seconds: int):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expires_at = time.time() + ttl_seconds
        entry = KeyEntry(kid, private_key, expires_at)
        self.keys[kid] = entry
        return entry

    def get_unexpired_keys(self):
        return [k for k in self.keys.values() if not k.is_expired()]

    def get_any_unexpired(self) -> Optional[KeyEntry]:
        keys = self.get_unexpired_keys()
        return keys[0] if keys else None

    def get_expired(self) -> Optional[KeyEntry]:
        for k in self.keys.values():
            if k.is_expired():
                return k
        return None

    def jwks(self) -> str:
        keys = [k.to_jwk() for k in self.get_unexpired_keys()]
        return json.dumps({"keys": keys})
