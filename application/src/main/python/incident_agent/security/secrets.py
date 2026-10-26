"""Encryption for connector secrets (API keys, passwords, service account JSON).

Secrets are encrypted with Fernet (AES-128-CBC + HMAC) before they reach the
database and are never returned by the API. The key comes from
CONNECTOR_SECRET_KEY, or is generated once into DATA_DIR/secret.key.
Losing the key means re-entering every connector secret.
"""

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, key: bytes | str):
        self.fernet = Fernet(key)

    @classmethod
    def from_env(cls, data_dir: str | Path) -> "SecretBox":
        key = os.environ.get("CONNECTOR_SECRET_KEY")
        if key:
            return cls(key)
        path = Path(data_dir) / "secret.key"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Fernet.generate_key())
            path.chmod(0o600)
        return cls(path.read_bytes())

    def encrypt(self, secrets: dict) -> str:
        return self.fernet.encrypt(json.dumps(secrets).encode()).decode()

    def decrypt(self, token: str | None) -> dict:
        if not token:
            return {}
        try:
            return json.loads(self.fernet.decrypt(token.encode()))
        except InvalidToken as e:
            raise ValueError("cannot decrypt connector secrets: wrong CONNECTOR_SECRET_KEY") from e
