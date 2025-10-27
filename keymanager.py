import sqlite3
import base64
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
        n = base64.urlsafe_b64encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode("utf-8")

        e = base64.urlsafe_b64encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode("utf-8")

        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        }


class KeyManager:
    def __init__(self, db_path="totally_not_my_privateKeys.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid TEXT PRIMARY KEY,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()

    def generate_key(self, kid: str, ttl_seconds: int = 3600):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        exp = int((datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).timestamp())

        # Insert or replace by kid (ensures unique string ID)
        self.cursor.execute(
            "INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)",
            (kid, pem_key, exp),
        )
        self.conn.commit()

        return KeyEntry(kid, private_key, exp)

    def _load_key(self, kid: str, pem_data: bytes, exp: int) -> KeyEntry:
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        return KeyEntry(kid, private_key, exp)

    def get_unexpired_keys(self):
        self.cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?",
            (int(time.time()),)
        )
        rows = self.cursor.fetchall()
        return [self._load_key(kid, pem, exp) for (kid, pem, exp) in rows]

    def get_any_unexpired(self) -> Optional[KeyEntry]:
        keys = self.get_unexpired_keys()
        return keys[0] if keys else None

    def get_expired(self) -> Optional[KeyEntry]:
        self.cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ?",
            (int(time.time()),)
        )
        row = self.cursor.fetchone()
        if row:
            kid, pem, exp = row
            return self._load_key(kid, pem, exp)
        return None

    def jwks(self) -> str:
        keys = [k.to_jwk() for k in self.get_unexpired_keys()]
        return json.dumps({"keys": keys})
