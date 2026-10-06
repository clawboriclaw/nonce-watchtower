"""Squads v4 multisig -> member keys + vault PDAs. Read-only.

Layout verified 2026-10-06 against Squads-Protocol/v4 @ af94153f (main):
  programs/squads_multisig_program/src/state/multisig.rs (struct Multisig, Member, Permissions)
  programs/squads_multisig_program/src/state/seeds.rs     (SEED_PREFIX = b"multisig", SEED_VAULT = b"vault")
  programs/squads_multisig_program/src/lib.rs             (declare_id!("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"))
  programs/squads_multisig_program/src/instructions/multisig_create.rs
                                                          (multisig PDA seeds [b"multisig", b"multisig", create_key])
  sdk/multisig/src/pda.ts getVaultPda: seeds [b"multisig", multisig, b"vault", u8 index]

Multisig account (Anchor + Borsh, so fields are packed in order; an Option is 1 tag byte and the
payload is present only when the tag is 1. `Multisig::size()` reserves 32 bytes for rent_collector
even when None, but that is allocated space, not serialized layout, so we decode sequentially):
    discriminator           [u8; 8]   sha256("account:Multisig")[:8] = e07479ba44a14fec
    create_key              Pubkey
    config_authority        Pubkey    (all-zero = autonomous; anything else can change members/threshold alone)
    threshold               u16
    time_lock               u32       seconds
    transaction_index       u64
    stale_transaction_index u64
    rent_collector          Option<Pubkey>
    bump                    u8
    members                 Vec<Member>   u32 length, then (key Pubkey, permissions.mask u8) each
  Permission bits: Initiate = 1, Vote = 2, Execute = 4; the program rejects masks >= 8.
Trailing bytes after the members are realloc padding and are ignored.
"""

import hashlib

from .base58 import b58decode, b58encode
from .decode import account_bytes
from .pda import create_program_address, find_program_address
from .rpc import RpcError, RpcUnavailable

SQUADS_V4_PROGRAM = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
SQUADS_V3_PROGRAM = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu"
MULTISIG_DISCRIMINATOR = hashlib.sha256(b"account:Multisig").digest()[:8]
DEFAULT_PUBKEY = "11111111111111111111111111111111"
PERMISSION_BITS = ((1, "initiate"), (2, "vote"), (4, "execute"))
MAX_MEMBERS = 65535  # Squads caps members at u16::MAX; a larger vec length is corrupt data


class MultisigDecodeError(ValueError):
    pass


def permission_names(mask):
    return [name for bit, name in PERMISSION_BITS if mask & bit]


def decode_multisig(raw: bytes):
    """Decode a Squads v4 Multisig account body. Raises MultisigDecodeError on anything unexpected."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(raw):
            raise MultisigDecodeError(f"account data ends at {len(raw)} bytes, needed {pos + n}")
        out = raw[pos : pos + n]
        pos += n
        return out

    if take(8) != MULTISIG_DISCRIMINATOR:
        raise MultisigDecodeError("discriminator is not Squads v4 Multisig (is this a vault, proposal or other account?)")
    create_key = b58encode(take(32))
    config_authority = b58encode(take(32))
    threshold = int.from_bytes(take(2), "little")
    time_lock = int.from_bytes(take(4), "little")
    transaction_index = int.from_bytes(take(8), "little")
    stale_transaction_index = int.from_bytes(take(8), "little")
    tag = take(1)[0]
    if tag == 0:
        rent_collector = None
    elif tag == 1:
        rent_collector = b58encode(take(32))
    else:
        raise MultisigDecodeError(f"rent_collector Option tag {tag} is not 0/1")
    bump = take(1)[0]
    n = int.from_bytes(take(4), "little")
    if n > MAX_MEMBERS:
        raise MultisigDecodeError(f"member count {n} is implausible")
    members = []
    for _ in range(n):
        key = b58encode(take(32))
        mask = take(1)[0]
        if mask >= 8:
            raise MultisigDecodeError(f"member {key} has unknown permission mask {mask}")
        members.append({"key": key, "permissions": mask, "permission_names": permission_names(mask)})
    if not members:
        raise MultisigDecodeError("multisig has no members")
    if len({m["key"] for m in members}) != len(members):
        raise MultisigDecodeError("duplicate member keys")
    return {
        "create_key": create_key,
        "config_authority": None if config_authority == DEFAULT_PUBKEY else config_authority,
        "threshold": threshold,
        "time_lock": time_lock,
        "transaction_index": transaction_index,
        "stale_transaction_index": stale_transaction_index,
        "rent_collector": rent_collector,
        "bump": bump,
        "members": members,
    }


def vault_pda(multisig: str, index: int = 0):
    """Squads v4 vault: PDA of [b"multisig", multisig, b"vault", u8 index] under the v4 program."""
    if not 0 <= index < 256:
        raise ValueError("vault index must fit in a u8")
    return find_program_address([b"multisig", b58decode(multisig), b"vault", bytes([index])], SQUADS_V4_PROGRAM)


def resolve_multisig(client, address):
    """Fetch and decode a Squads v4 multisig. Any status but "ok" means the member list is UNKNOWN."""
    try:
        res = client.call("getAccountInfo", [address, {"encoding": "base64"}])
    except (RpcError, RpcUnavailable) as e:
        return {"address": address, "status": "unavailable", "error": str(e)}
    value = (res or {}).get("value") if isinstance(res, dict) else None
    if not value:
        return {"address": address, "status": "missing", "error": "no account at this address"}
    owner = value.get("owner")
    if owner == SQUADS_V3_PROGRAM:
        return {"address": address, "status": "unsupported_v3", "owner_program": owner,
                "error": "this is a Squads v3 (SMPLec…) multisig; only v4 is decoded. List its member keys "
                         "yourself."}
    if owner != SQUADS_V4_PROGRAM:
        return {"address": address, "status": "wrong_owner", "owner_program": owner,
                "error": f"account is owned by {owner}, not the Squads v4 program {SQUADS_V4_PROGRAM}; refusing to "
                         "read members from it"}
    try:
        ms = decode_multisig(account_bytes(value))
    except (ValueError, TypeError) as e:
        return {"address": address, "status": "undecodable", "owner_program": owner, "error": str(e)}
    # Self-check: a genuine v4 multisig lives at PDA([b"multisig", b"multisig", create_key], bump).
    derived = create_program_address([b"multisig", b"multisig", b58decode(ms["create_key"]), bytes([ms["bump"]])],
                                     SQUADS_V4_PROGRAM)
    if derived != address:
        return {"address": address, "status": "undecodable", "owner_program": owner,
                "error": "decoded create_key/bump do not derive this address; layout mismatch, members not trusted"}
    vault, vault_bump = vault_pda(address, 0)
    return {"address": address, "status": "ok", "owner_program": owner, **ms,
            "vaults": [{"index": 0, "address": vault, "bump": vault_bump}]}


def watched_keys(ms):
    """[(pubkey, role)] for a resolved multisig: every member, vault 0, and a config authority if set."""
    out = [(m["key"], f"member {i + 1} ({'+'.join(m['permission_names']) or 'no permissions'})")
           for i, m in enumerate(ms["members"])]
    out += [(v["address"], f"vault {v['index']}") for v in ms["vaults"]]
    if ms.get("config_authority"):
        out.append((ms["config_authority"], "config authority"))
    return out
