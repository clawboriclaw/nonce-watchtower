"""wallets.toml loading. Secrets (RPC / webhook URLs) are read from env vars by name."""

import json
import os
import tempfile
import tomllib

from .base58 import require_pubkey
from .redact import scrub_obj
from .rpc import DEFAULT_MAX_BLOCK_AGE, DEFAULT_MAX_SLOT_LAG, DEFAULT_RPC, RPC_ENV_VAR
from .ws import WS_ENV_VAR

WEBHOOK_ENV_VAR = "WATCHTOWER_WEBHOOK_URL"
TELEGRAM_TOKEN_ENV_VAR = "WATCHTOWER_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ENV_VAR = "WATCHTOWER_TELEGRAM_CHAT_ID"
TELEGRAM_THREAD_ENV_VAR = "WATCHTOWER_TELEGRAM_THREAD_ID"
REFERENCE_RPC_ENV_VAR = "WATCHTOWER_REFERENCE_RPC_URL"
DISCORD_ENV_VAR = "WATCHTOWER_DISCORD_WEBHOOK_URL"
DEFAULT_DEDUP_SECONDS = 1800

ENV_NAME_KEYS = {
    "rpc_url_env": RPC_ENV_VAR,
    "webhook_url_env": WEBHOOK_ENV_VAR,
    "ws_url_env": WS_ENV_VAR,
    "telegram_bot_token_env": TELEGRAM_TOKEN_ENV_VAR,
    "telegram_chat_id_env": TELEGRAM_CHAT_ENV_VAR,
    "telegram_thread_id_env": TELEGRAM_THREAD_ENV_VAR,
    "reference_rpc_url_env": REFERENCE_RPC_ENV_VAR,
    "discord_webhook_url_env": DISCORD_ENV_VAR,
}
# Values that are credentials. They are refused in the file so they never end up in a repo or a backup.
INLINE_SECRET_KEYS = {"rpc_url", "webhook_url", "ws_url", "telegram_bot_token", "discord_webhook_url", "reference_rpc_url"}
TOP_LEVEL_KEYS = ({"wallets", "mints", "programs", "squads", "state_file", "telegram_chat_id", "alert_dedup_seconds",
                   "max_slot_lag", "max_block_age"}
                  | set(ENV_NAME_KEYS) | INLINE_SECRET_KEYS)


class ConfigError(ValueError):
    pass


def load_config(path):
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read config {path}: {e}") from None

    unknown = set(raw) - TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")
    wallets = []
    for i, w in enumerate(raw.get("wallets", [])):
        if isinstance(w, str):
            w = {"pubkey": w}
        if not isinstance(w, dict) or "pubkey" not in w:
            raise ConfigError(f"wallets[{i}] needs a pubkey")
        extra = set(w) - {"pubkey", "label"}
        if extra:
            # TOML trap: keys written after a [[wallets]] header belong to that wallet.
            # Silently ignoring e.g. `mints = [...]` here would be an unmonitored blind spot.
            raise ConfigError(
                f"wallets[{i}] has unexpected key(s) {', '.join(sorted(extra))}; top-level settings such as "
                "mints/programs must appear BEFORE the first [[wallets]] block"
            )
        try:
            require_pubkey(w["pubkey"], f"wallets[{i}].pubkey")
        except ValueError as e:
            raise ConfigError(str(e)) from None
        wallets.append({"pubkey": w["pubkey"], "label": str(w.get("label", ""))})
    if len({w["pubkey"] for w in wallets}) != len(wallets):
        raise ConfigError("duplicate wallet pubkey in config")

    def keys(name):
        vals = raw.get(name, [])
        if not isinstance(vals, list):
            raise ConfigError(f"{name} must be a list")
        try:
            return [require_pubkey(v, name[:-1]) for v in vals]
        except ValueError as e:
            raise ConfigError(str(e)) from None

    cfg = {
        "wallets": wallets,
        "mints": keys("mints"),
        "programs": keys("programs"),
        "squads": keys("squads"),
        **{k: raw.get(k, default) for k, default in ENV_NAME_KEYS.items()},
        "state_file": raw.get("state_file"),
        "telegram_chat_id": raw.get("telegram_chat_id"),
        "alert_dedup_seconds": raw.get("alert_dedup_seconds", DEFAULT_DEDUP_SECONDS),
        "max_slot_lag": raw.get("max_slot_lag", DEFAULT_MAX_SLOT_LAG),
        "max_block_age": raw.get("max_block_age", DEFAULT_MAX_BLOCK_AGE),
    }
    inline = sorted(INLINE_SECRET_KEYS & set(raw))
    if inline:
        raise ConfigError(
            f"{', '.join(inline)} in the config file: put RPC/WebSocket/webhook URLs and bot tokens in environment "
            "variables (rpc_url_env, ws_url_env, webhook_url_env, telegram_bot_token_env, discord_webhook_url_env, "
            "reference_rpc_url_env), "
            "not in the config file: they are credentials"
        )
    for k in ENV_NAME_KEYS:
        if not isinstance(cfg[k], str) or not cfg[k]:
            raise ConfigError(f"{k} must be the NAME of an environment variable")
    if cfg["telegram_chat_id"] is not None:
        if isinstance(cfg["telegram_chat_id"], bool) or not isinstance(cfg["telegram_chat_id"], (int, str)):
            raise ConfigError("telegram_chat_id must be a number or an @channel name")
        cfg["telegram_chat_id"] = str(cfg["telegram_chat_id"])
    lag = cfg["max_slot_lag"]
    if isinstance(lag, bool) or not isinstance(lag, int) or lag < 0:
        raise ConfigError("max_slot_lag must be a whole number of slots >= 0")
    age = cfg["max_block_age"]
    if isinstance(age, bool) or not isinstance(age, int) or age <= 0:
        raise ConfigError("max_block_age must be a whole number of seconds > 0")
    d = cfg["alert_dedup_seconds"]
    if isinstance(d, bool) or not isinstance(d, int) or d < 0:
        raise ConfigError("alert_dedup_seconds must be a whole number of seconds >= 0")
    if not wallets and not cfg["mints"] and not cfg["programs"] and not cfg["squads"]:
        raise ConfigError("config watches nothing (no wallets, squads, mints or programs)")
    if cfg["state_file"] is None:
        cfg["state_file"] = os.path.splitext(os.path.abspath(path))[0] + ".state.json"
    elif not os.path.isabs(cfg["state_file"]):
        cfg["state_file"] = os.path.join(os.path.dirname(os.path.abspath(path)), cfg["state_file"])
    return cfg


def resolve_rpc(cli_value, env_name=RPC_ENV_VAR):
    return cli_value or os.environ.get(env_name) or DEFAULT_RPC


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_state(path, state):
    """Atomic write, mode 0600."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".watchtower-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(scrub_obj(state), f, indent=1, sort_keys=True)  # no secret ever lands on disk
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
