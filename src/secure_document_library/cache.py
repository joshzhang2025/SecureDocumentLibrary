from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

def _key(environment_name: str) -> bytes:
    raw = os.environ.get(environment_name, "")
    try: value = base64.b64decode(raw, validate=True)
    except Exception as exc: raise ValueError(f"{environment_name} must be a base64 32-byte key") from exc
    if len(value) != 32: raise ValueError(f"{environment_name} must be a base64 32-byte key")
    return value

class EncryptedCache:
    """AES-256-GCM content-addressed cache; no plaintext is written to disk."""
    def __init__(self, root: Path, key_id: str = "cache-v1"):
        self.root, self.key_id = root.resolve(), key_id
        self.key = _key("SECURE_LIBRARY_CACHE_KEY")
        self.search_key = _key("SECURE_LIBRARY_SEARCH_KEY")
        if secrets.compare_digest(self.key, self.search_key):
            raise ValueError("SECURE_LIBRARY_CACHE_KEY and SECURE_LIBRARY_SEARCH_KEY must be different")

    def _file(self, object_id: str) -> Path: return self.root / "objects" / object_id[:2] / f"{object_id}.bin"

    def put(self, text: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        object_id = hashlib.sha256(normalized.encode()).hexdigest(); destination = self._file(object_id)
        if destination.exists(): self.get(object_id); return object_id
        metadata = {"version": 1, "object_id": object_id, "key_id": self.key_id, "algorithm": "AES-256-GCM"}
        aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(); nonce = secrets.token_bytes(12)
        payload = {**metadata, "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(AESGCM(self.key).encrypt(nonce, normalized.encode(), aad)).decode()}
        destination.parent.mkdir(parents=True, exist_ok=True); temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8"); temporary.replace(destination)
        return object_id

    def get(self, object_id: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        payload = json.loads(self._file(object_id).read_text(encoding="utf-8"))
        metadata = {name: payload[name] for name in ("version", "object_id", "key_id", "algorithm")}
        if payload["object_id"] != object_id or payload["key_id"] != self.key_id: raise ValueError("Invalid cache metadata")
        try: text = AESGCM(self.key).decrypt(base64.b64decode(payload["nonce"]), base64.b64decode(payload["ciphertext"]), json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).decode()
        except Exception as exc: raise ValueError("Cache authentication failed") from exc
        if hashlib.sha256(text.encode()).hexdigest() != object_id: raise ValueError("Cache hash mismatch")
        return text
