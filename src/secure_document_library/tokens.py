from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter

TOKEN = re.compile(r"[A-Za-z0-9]+(?:[._:/-][A-Za-z0-9]+)*|[\u3400-\u9fff]+")
SEPARATOR = re.compile(r"[._:/-]+")

def tokenize(text: str) -> list[str]:
    values: list[str] = []
    for match in TOKEN.finditer(text.lower()):
        value = match.group(0)
        if "\u3400" <= value[0] <= "\u9fff":
            values.extend([value, *(value[i:i + 2] for i in range(len(value) - 1))])
        else:
            values.append(value); values.extend(part for part in SEPARATOR.split(value) if part != value)
    return values

def digest(token: str, key: bytes) -> str:
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()

def frequencies(text: str, key: bytes) -> dict[str, int]:
    return dict(Counter(digest(token, key) for token in tokenize(text)))

