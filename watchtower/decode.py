"""Binary layouts, verified against Solana source (anza-xyz/solana-sdk, 2026-10-06).

Nonce account (System program owned, 80 bytes, bincode):
    nonce::versions::Versions  enum tag u32   offset 0   (0 = Legacy, 1 = Current)
    nonce::state::State        enum tag u32   offset 4   (0 = Uninitialized, 1 = Initialized)
    Data.authority             Pubkey         offset 8   (32 bytes)
    Data.durable_nonce         Hash           offset 40  (32 bytes)
    Data.fee_calculator        u64            offset 72  (lamports_per_signature)
  State::size() == 80 (asserted by test_nonce_state_size upstream).

BPF upgradeable loader (UpgradeableLoaderState, bincode):
    Program     { tag u32 = 2, programdata_address: Pubkey }                 36 bytes
    ProgramData { tag u32 = 3, slot: u64, upgrade_authority: Option<Pubkey> }
                  option tag u8 at offset 12, pubkey at offset 13; header = 45 bytes
"""

import base64

from .base58 import b58encode

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
LOADER_V4 = "LoaderV411111111111111111111111111111111111"
NON_UPGRADEABLE_LOADERS = {
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
}

NONCE_ACCOUNT_SIZE = 80
NONCE_AUTHORITY_OFFSET = 8
PROGRAMDATA_HEADER_SIZE = 45


def account_bytes(account: dict) -> bytes:
    data = account.get("data")
    if not (isinstance(data, list) and len(data) == 2 and data[1] == "base64"):
        raise ValueError("expected base64-encoded account data")
    return base64.b64decode(data[0], validate=True)


def decode_nonce(raw: bytes):
    """Return a dict for an initialized nonce account, or None if `raw` is not one."""
    if len(raw) != NONCE_ACCOUNT_SIZE:
        return None
    version = int.from_bytes(raw[0:4], "little")
    state = int.from_bytes(raw[4:8], "little")
    if version not in (0, 1) or state != 1:
        return None
    return {
        "version": "current" if version == 1 else "legacy",
        "authority": b58encode(raw[8:40]),
        "nonce": b58encode(raw[40:72]),
        "lamports_per_signature": int.from_bytes(raw[72:80], "little"),
    }


def decode_program(raw: bytes):
    """Upgradeable-loader Program account -> programdata address, else None."""
    if len(raw) < 36 or int.from_bytes(raw[0:4], "little") != 2:
        return None
    return b58encode(raw[4:36])


def decode_programdata_header(raw: bytes):
    """Upgradeable-loader ProgramData header -> {slot, upgrade_authority|None}, else None."""
    if len(raw) < 13 or int.from_bytes(raw[0:4], "little") != 3:
        return None
    slot = int.from_bytes(raw[4:12], "little")
    tag = raw[12]
    if tag == 0:
        return {"slot": slot, "upgrade_authority": None}
    if tag == 1 and len(raw) >= PROGRAMDATA_HEADER_SIZE:
        return {"slot": slot, "upgrade_authority": b58encode(raw[13:45])}
    return None
