"""SPL Token / Token-2022 account and mint layouts, decoded locally from base64 bytes.

Security scan 2026-11-08 (finding 1): every field that decides a token finding (owner, delegate, delegated amount,
state, close authority, mint supply / decimals / freeze authority, permanent delegate) is read from the account bytes
here, never from the endpoint's jsonParsed view. Layouts (spl-token / spl-token-2022 `state.rs`, `extension/mod.rs`),
checked field-by-field against live mainnet getMultipleAccounts / getTokenAccountsByOwner answers in both encodings
(USDC, PYUSD and PUMP mints; SPL and Token-2022 accounts of the test delegator), 2026-11-09:

Account (165 bytes; Token-2022 appends account-type byte 2 at 165 and TLV extensions):
    mint 0..32 · owner 32..64 · amount u64 64..72 · delegate COption<Pubkey> 72..108 (u32 tag + 32)
    state u8 108 (0 uninitialized, 1 initialized, 2 frozen) · is_native COption<u64> 109..121
    delegated_amount u64 121..129 · close_authority COption<Pubkey> 129..165
Mint (82 bytes; Token-2022 pads to 165, account-type byte 1 at 165, TLV from 166 as u16 type, u16 length, value):
    mint_authority COption<Pubkey> 0..36 · supply u64 36..44 · decimals u8 44 · is_initialized u8 45
    freeze_authority COption<Pubkey> 46..82
    extensions: MintCloseAuthority = 3 (32), PermanentDelegate = 12 (32), TransferHook = 14 (authority 32 +
    program_id 32); each an OptionalNonZeroPubkey (all-zero = None).

Anything that does not fit these layouts raises ValueError (NotAMint for a well-formed token-program account of another
kind): the caller reports the check as unavailable, never as clean.
"""

from .base58 import b58encode
from .decode import TOKEN_2022_PROGRAM, TOKEN_PROGRAM

ACCOUNT_SIZE = 165
MINT_SIZE = 82
MULTISIG_SIZE = 355
ACCOUNT_TYPE_MINT = 1
ACCOUNT_TYPE_ACCOUNT = 2
EXT_MINT_CLOSE_AUTHORITY = 3
EXT_INTEREST_BEARING = 10
EXT_PERMANENT_DELEGATE = 12
EXT_TRANSFER_HOOK = 14
EXT_SCALED_UI_AMOUNT = 25  # ExtensionType enum order upstream (2026-11-09): ... ConfidentialMintBurn 24, ScaledUiAmount 25
_STATES = {1: "initialized", 2: "frozen"}
_ZERO32 = bytes(32)


class NotAMint(ValueError):
    """A well-formed token-program account of another kind (token account, multisig, uninitialized mint)."""


def _u64(raw, at):
    return int.from_bytes(raw[at : at + 8], "little")


def _coption_key(raw, at):
    tag = int.from_bytes(raw[at : at + 4], "little")
    if tag == 0:
        return None
    if tag == 1:
        return b58encode(raw[at + 4 : at + 36])
    raise ValueError(f"invalid COption tag {tag} at offset {at}")


def _nonzero_key(raw):
    if len(raw) != 32:
        raise ValueError("extension pubkey has the wrong length")
    return None if raw == _ZERO32 else b58encode(raw)


def _check_program(program):
    if program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise ValueError(f"account is not owned by a token program ({program!r})")


def ui_amount_string(amount, decimals):
    """The RPC's uiAmountString: amount / 10**decimals, trailing zeros (and a bare '.') trimmed."""
    if not decimals:
        return str(amount)
    s = str(amount).rjust(decimals + 1, "0")
    return (s[:-decimals] + "." + s[-decimals:]).rstrip("0").rstrip(".")


def decode_token_account(raw, program):
    """Initialized token account owned by `program` -> dict of decision fields; ValueError otherwise."""
    _check_program(program)
    if len(raw) != ACCOUNT_SIZE:
        if program == TOKEN_PROGRAM or len(raw) <= ACCOUNT_SIZE or raw[ACCOUNT_SIZE] != ACCOUNT_TYPE_ACCOUNT:
            raise ValueError(f"not a token account ({len(raw)} bytes)")
    state = _STATES.get(raw[108])
    if state is None:
        raise ValueError(f"token account state byte {raw[108]} is not initialized/frozen")
    if int.from_bytes(raw[109:113], "little") not in (0, 1):
        raise ValueError("invalid is_native COption tag")
    return {
        "mint": b58encode(raw[0:32]),
        "owner": b58encode(raw[32:64]),
        "amount": str(_u64(raw, 64)),
        "delegate": _coption_key(raw, 72),
        "state": state,
        "delegated_amount": str(_u64(raw, 121)),
        "close_authority": _coption_key(raw, 129),
    }


def _mint_extensions(raw):
    """Token-2022 TLV area -> {type: value bytes}, following upstream `try_for_each_tlv_extension_type`
    (interface/src/extension/mod.rs): fewer than 2 bytes left, or an Uninitialized (0) type, is the end. That end
    matters: an extended account that would be exactly Multisig::LEN (355) gets 2 zero padding bytes (357)."""
    exts, at = {}, ACCOUNT_SIZE + 1
    while at < len(raw):
        if at + 2 > len(raw):
            break
        etype = int.from_bytes(raw[at : at + 2], "little")
        if etype == 0:
            break
        if at + 4 > len(raw):
            raise ValueError("truncated mint extension header")
        length = int.from_bytes(raw[at + 2 : at + 4], "little")
        value = raw[at + 4 : at + 4 + length]
        if len(value) != length:
            raise ValueError(f"truncated mint extension {etype}")
        if etype in exts:
            raise ValueError(f"duplicate mint extension {etype}")
        exts[etype] = value
        at += 4 + length
    return exts


def decode_mint(raw, program):
    """Initialized mint owned by `program` -> dict of authority fields; ValueError for anything else."""
    _check_program(program)
    exts = {}
    if (len(raw) in (ACCOUNT_SIZE, MULTISIG_SIZE)
            or (program == TOKEN_2022_PROGRAM and len(raw) > ACCOUNT_SIZE and raw[ACCOUNT_SIZE] == ACCOUNT_TYPE_ACCOUNT)):
        raise NotAMint(f"token-program account of {len(raw)} bytes is not a mint")
    if len(raw) != MINT_SIZE:
        if (program == TOKEN_PROGRAM or len(raw) <= ACCOUNT_SIZE or raw[ACCOUNT_SIZE] != ACCOUNT_TYPE_MINT
                or any(raw[MINT_SIZE:ACCOUNT_SIZE])):
            raise ValueError(f"not a mint ({len(raw)} bytes)")
        exts = _mint_extensions(raw)
    if raw[45] != 1:
        raise NotAMint("mint is not initialized")
    hook = exts.get(EXT_TRANSFER_HOOK)
    if hook is not None and len(hook) != 64:
        raise ValueError("transfer hook extension has the wrong length")
    for etype in (EXT_MINT_CLOSE_AUTHORITY, EXT_PERMANENT_DELEGATE):
        if etype in exts and len(exts[etype]) != 32:
            raise ValueError(f"mint extension {etype} has the wrong length")
    return {
        "mint_authority": _coption_key(raw, 0),
        "supply": str(_u64(raw, 36)),
        "decimals": raw[44],
        "freeze_authority": _coption_key(raw, 46),
        "close_authority": _nonzero_key(exts[EXT_MINT_CLOSE_AUTHORITY]) if EXT_MINT_CLOSE_AUTHORITY in exts else None,
        "permanent_delegate": _nonzero_key(exts[EXT_PERMANENT_DELEGATE]) if EXT_PERMANENT_DELEGATE in exts else None,
        "transfer_hook_authority": _nonzero_key(hook[:32]) if hook is not None else None,
        "transfer_hook_program": _nonzero_key(hook[32:]) if hook is not None else None,
        # The display amount of these mints is not amount / 10**decimals; we do not compute it (raw units only).
        "ui_scaled": EXT_INTEREST_BEARING in exts or EXT_SCALED_UI_AMOUNT in exts,
    }
