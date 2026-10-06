"""Minimal base58 (Bitcoin alphabet) codec for Solana public keys. Stdlib only."""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, rem = divmod(n, 58)
        out.append(ALPHABET[rem])
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise ValueError("empty base58 string")
    n = 0
    for ch in text:
        try:
            n = n * 58 + _INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base58 character {ch!r}") from None
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + body


def is_pubkey(text: str) -> bool:
    """True if `text` is base58 that decodes to exactly 32 bytes (and round-trips)."""
    if not isinstance(text, str) or not (32 <= len(text) <= 44):
        return False
    try:
        raw = b58decode(text)
    except ValueError:
        return False
    return len(raw) == 32 and b58encode(raw) == text


def require_pubkey(text: str, what: str = "public key") -> str:
    if not is_pubkey(text):
        raise ValueError(f"not a valid Solana {what}: {text!r}")
    return text
