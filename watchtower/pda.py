"""Program-derived addresses (PDAs), stdlib only.

Mirrors solana-program `Pubkey::create_program_address` / `find_program_address`:
    candidate = sha256(seed_0 || ... || seed_n || [bump] || program_id || b"ProgramDerivedAddress")
and a candidate is valid only if it is NOT a point on the ed25519 curve. "On curve" follows
curve25519-dalek `CompressedEdwardsY::decompress().is_some()`: the top bit is the x sign, y is the
low 255 bits read mod p, and the point exists iff (y^2 - 1) / (d*y^2 + 1) is a square mod p.
Cross-checked in tests against real associated-token accounts and real Squads vaults.
"""

import hashlib

from .base58 import b58decode, b58encode

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
PDA_MARKER = b"ProgramDerivedAddress"
MAX_SEED_LEN = 32
MAX_SEEDS = 16


def is_on_curve(raw: bytes) -> bool:
    if len(raw) != 32:
        raise ValueError("expected 32 bytes")
    # Non-canonical y >= p (K3 review): REDUCED mod p, not rejected. This matches curve25519-dalek, which Solana's
    # bytes_are_curve_point calls: decompress -> FieldElement::from_bytes "does not check that the input used the
    # canonical representative ... it will happily decode 2^255 - 18 to 1" (curve25519-dalek @ 97a020d1,
    # backend/serial/u64/field.rs). Only 19 of 2^255 encodings are non-canonical (~2^-250 per hash) anyway.
    y = (int.from_bytes(raw, "little") & ((1 << 255) - 1)) % _P
    yy = y * y % _P
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
    if u == 0:
        return True  # x = 0
    x2 = u * pow(v, _P - 2, _P) % _P
    return pow(x2, (_P - 1) // 2, _P) == 1  # Euler's criterion: x^2 has a root


def create_program_address(seeds, program_id: str):
    """Return the PDA as base58, or None if the hash lands on the curve (that bump is invalid)."""
    if len(seeds) > MAX_SEEDS or any(len(s) > MAX_SEED_LEN for s in seeds):
        raise ValueError("too many seeds or seed longer than 32 bytes")
    h = hashlib.sha256()
    for s in seeds:
        h.update(s)
    h.update(b58decode(program_id))
    h.update(PDA_MARKER)
    out = h.digest()
    return None if is_on_curve(out) else b58encode(out)


def find_program_address(seeds, program_id: str):
    """(address, bump) for the highest bump in 255..0 that yields an off-curve address."""
    for bump in range(255, -1, -1):
        addr = create_program_address(list(seeds) + [bytes([bump])], program_id)
        if addr is not None:
            return addr, bump
    raise ValueError("no viable bump seed")
