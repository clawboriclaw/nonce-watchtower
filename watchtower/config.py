"""wallets.toml loading. Secrets (RPC / webhook URLs) are read from env vars by name."""

import json
import os
import tempfile
import tomllib

from .base58 import require_pubkey
from .rpc import DEFAULT_RPC, RPC_ENV_VAR

WEBHOOK_ENV_VAR = "WATCHTOWER_WEBHOOK_URL"


TOP_LEVEL_KEYS = {"wallets", "mints", "programs", "squads", "rpc_url_env", "webhook_url_env", "state_file", "rpc_url", "webhook_url"}


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
        "rpc_url_env": raw.get("rpc_url_env", RPC_ENV_VAR),
        "webhook_url_env": raw.get("webhook_url_env", WEBHOOK_ENV_VAR),
        "state_file": raw.get("state_file"),
    }
    if "rpc_url" in raw or "webhook_url" in raw:
        raise ConfigError(
            "put RPC/webhook URLs in environment variables (rpc_url_env / webhook_url_env), not in the config "
            "file: they usually embed credentials"
        )
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
            json.dump(state, f, indent=1, sort_keys=True)
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
