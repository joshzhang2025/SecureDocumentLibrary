"""Generation-aware encrypted cache primitives."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path


_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{64}$")


def _decode(value: str, name: str) -> bytes:
    try:
        key = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{name} must be a base64 32-byte key") from exc
    if len(key) != 32:
        raise ValueError(f"{name} must be a base64 32-byte key")
    return key


def _fingerprint(key: bytes, purpose: str) -> str:
    return hmac.new(key, f"secure-document-library:{purpose}:fingerprint:v1".encode(), hashlib.sha256).hexdigest()


def _keyring(active_name: str, keys_name: str, default_id: str) -> tuple[str, dict[str, bytes]]:
    active_id = os.environ.get(f"{active_name}_ID", default_id)
    if not _KEY_ID.fullmatch(active_id):
        raise ValueError(f"{active_name}_ID_INVALID")
    values: dict[str, bytes] = {}
    encoded = os.environ.get(keys_name)
    if encoded:
        try:
            payload = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{keys_name}_INVALID") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"{keys_name}_INVALID")
        for key_id, value in payload.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id) or not isinstance(value, str):
                raise ValueError(f"{keys_name}_INVALID")
            values[key_id] = _decode(value, keys_name)
    active_encoded = os.environ.get(active_name, "")
    if active_encoded:
        active = _decode(active_encoded, active_name)
        previous = values.get(active_id)
        if previous is not None and not secrets.compare_digest(previous, active):
            raise ValueError(f"{active_name}_KEYRING_ACTIVE_MISMATCH")
        values[active_id] = active
    if active_id not in values:
        raise ValueError(f"{active_name}_MISSING")
    return active_id, values


@dataclass(frozen=True)
class KeyProvider:
    """Resolved key generations. Construct once; never reread environment state."""
    content_key_id: str
    content_keys: dict[str, bytes]
    search_key_id: str
    search_keys: dict[str, bytes]

    @classmethod
    def from_environment(cls) -> "KeyProvider":
        content_id, content = _keyring("SECURE_LIBRARY_CACHE_KEY", "SECURE_LIBRARY_CACHE_KEYS", "content-v1")
        search_id, search = _keyring("SECURE_LIBRARY_SEARCH_KEY", "SECURE_LIBRARY_SEARCH_KEYS", "search-v1")
        if any(secrets.compare_digest(a, b) for a in content.values() for b in search.values()):
            raise ValueError("SECURE_LIBRARY_CACHE_KEY and SECURE_LIBRARY_SEARCH_KEY must be different")
        return cls(content_id, content, search_id, search)

    def content_key(self, key_id: str | None = None) -> bytes:
        try:
            return self.content_keys[key_id or self.content_key_id]
        except KeyError as exc:
            raise ValueError("CONTENT_KEY_GENERATION_UNAVAILABLE") from exc

    def search_key(self, key_id: str | None = None) -> bytes:
        try:
            return self.search_keys[key_id or self.search_key_id]
        except KeyError as exc:
            raise ValueError("SEARCH_KEY_GENERATION_UNAVAILABLE") from exc

    def content_fingerprint(self, key_id: str | None = None) -> str:
        return _fingerprint(self.content_key(key_id), "content")

    def search_fingerprint(self, key_id: str | None = None) -> str:
        return _fingerprint(self.search_key(key_id), "search")


class EncryptedCache:
    """AES-256-GCM cache with v2 generation-specific IDs and v1 read support."""
    def __init__(self, root: Path, provider: KeyProvider | None = None):
        self.root = root.resolve()
        self.provider = provider or KeyProvider.from_environment()
        self.key_id = self.provider.content_key_id
        self.key = self.provider.content_key()
        self.key_fingerprint = self.provider.content_fingerprint()
        self.search_key = self.provider.search_key()
        self.search_key_id = self.provider.search_key_id
        self.search_key_fingerprint = self.provider.search_fingerprint()

    def _file(self, object_id: str) -> Path:
        if not _OBJECT_ID.fullmatch(object_id):
            raise ValueError("CACHE_REFERENCE_INVALID")
        return self.root / "objects" / object_id[:2] / f"{object_id}.bin"

    @staticmethod
    def _normalized(text: str) -> str:
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def _v2_object_id(self, content_hash: str, fingerprint: str | None = None) -> str:
        return hashlib.sha256(f"secure-cache-v2:{fingerprint or self.key_fingerprint}:{content_hash}".encode()).hexdigest()

    def put(self, text: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        normalized = self._normalized(text)
        content_hash = hashlib.sha256(normalized.encode()).hexdigest()
        object_id = self._v2_object_id(content_hash)
        destination = self._file(object_id)
        if destination.exists():
            self.get(object_id)
            return object_id
        metadata = {"version": 2, "object_id": object_id, "content_hash": content_hash, "key_id": self.key_id, "key_fingerprint": self.key_fingerprint, "algorithm": "AES-256-GCM"}
        nonce = secrets.token_bytes(12)
        aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        payload = {**metadata, "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(AESGCM(self.key).encrypt(nonce, normalized.encode(), aad)).decode()}
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        temporary.replace(destination)
        return object_id

    def get(self, object_id: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        path = self._file(object_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            version = int(payload["version"])
            key_id = payload["key_id"]
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise ValueError("Invalid cache metadata")
            try:
                key = self.provider.content_key(key_id)
            except ValueError:
                # Pre-generation objects used the historical cache-v1 ID while
                # relying on the only configured content key.
                if version == 1 and key_id == "cache-v1":
                    key = self.provider.content_key()
                else:
                    raise
            if version == 2:
                metadata = {name: payload[name] for name in ("version", "object_id", "content_hash", "key_id", "key_fingerprint", "algorithm")}
                if payload["object_id"] != object_id or payload["key_fingerprint"] != self.provider.content_fingerprint(key_id):
                    raise ValueError("Invalid cache metadata")
            elif version == 1:
                metadata = {name: payload[name] for name in ("version", "object_id", "key_id", "algorithm")}
                if payload["object_id"] != object_id:
                    raise ValueError("Invalid cache metadata")
            else:
                raise ValueError("Invalid cache metadata")
            aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
            text = AESGCM(key).decrypt(base64.b64decode(payload["nonce"], validate=True), base64.b64decode(payload["ciphertext"], validate=True), aad).decode()
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("Cache authentication failed") from exc
        content_hash = hashlib.sha256(text.encode()).hexdigest()
        expected = self._v2_object_id(content_hash, self.provider.content_fingerprint(key_id)) if version == 2 else content_hash
        if not secrets.compare_digest(expected, object_id):
            raise ValueError("Cache hash mismatch")
        return text

    def verify(self, object_ids: list[str] | tuple[str, ...]) -> dict[str, int | bool]:
        checked = 0
        for object_id in object_ids:
            try:
                self.get(object_id)
            except (OSError, ValueError, KeyError):
                return {"ok": False, "checked": checked}
            checked += 1
        return {"ok": True, "checked": checked}
