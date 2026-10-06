"""Turn scan reports into comparable snapshots and diff them into alerts.

Rule: if a check could not run this cycle, the previous known values for that
check are carried forward unchanged. An outage must never read as "the nonce
account disappeared" or "the delegate was revoked".
"""

from .decode import TOKEN_2022_PROGRAM
from .scan import is_nft_lock, lock_severity, outside_creator_text, outside_fee_payer_text

SNAPSHOT_VERSION = 2
COVERAGE_OK = ("ok", "missing", "not_a_mint", "not_a_program")
MINT_FIELDS = (
    "mint_authority",
    "freeze_authority",
    "permanent_delegate",
    "close_authority",
    "transfer_hook_program",
    "transfer_hook_authority",
)


def empty_snapshot():
    return {"v": SNAPSHOT_VERSION, "nonces": {}, "tokens": {}, "perm": {}, "mints": {}, "programs": {}, "coverage": {},
            "multisigs": {}}


def normalize(snap):
    """Fill sections added after v1 so an older state file still diffs (and its nonces keep their history)."""
    if snap is None:
        return None
    out = empty_snapshot()
    out.update(snap)
    return out


def squads_fallback(snap):
    """{multisig: [[pubkey, role], ...]} last known, for watching members while resolution is failing."""
    return {a: m["watched_keys"] for a, m in ((snap or {}).get("multisigs") or {}).items() if m.get("watched_keys")}


def known_provenance(snap):
    return {a: v["provenance"] for a, v in ((snap or {}).get("nonces") or {}).items()
            if (v.get("provenance") or {}).get("status") == "ok"}


def snapshot(report, previous=None):
    prev = normalize(previous) or empty_snapshot()
    snap = empty_snapshot()
    for ms in report.get("multisigs", []):
        addr = ms["address"]
        # "missing" is fine for a mint, but a missing multisig means its members are unknown.
        snap["coverage"][f"squads:{addr}"] = "multisig_" + ms["status"] if ms["status"] == "missing" else ms["status"]
        if ms["status"] == "ok":
            snap["multisigs"][addr] = {
                "threshold": ms["threshold"],
                "time_lock": ms["time_lock"],
                "config_authority": ms.get("config_authority"),
                "members": {m["key"]: m["permissions"] for m in ms["members"]},
                "watched_keys": [[k["pubkey"], k["role"]] for k in ms["watched_keys"]],
            }
        elif addr in prev["multisigs"]:
            snap["multisigs"][addr] = prev["multisigs"][addr]
    for w in report["wallets"]:
        pk = w["pubkey"]
        n = w["nonces"]
        snap["coverage"][f"nonces:{pk}"] = n["status"]
        if n["status"] == "ok":
            for it in n["items"]:
                pv = it.get("provenance")
                if pv is not None:
                    snap["coverage"][f"provenance:{it['account']}"] = pv["status"]
                    # A lookup that failed this cycle must not erase a settled answer (same rule as the squads
                    # member carry-forward): keep the last ok record, so nothing re-fires when coverage returns.
                    prev_pv = (prev["nonces"].get(it["account"]) or {}).get("provenance") or {}
                    if pv.get("status") != "ok" and prev_pv.get("status") == "ok":
                        pv = prev_pv
                snap["nonces"][it["account"]] = {
                    "wallet": pk,
                    "authority": it["authority"],
                    "nonce": it["nonce"],
                    "version": it["version"],
                    "provenance": pv,
                }
        else:
            snap["nonces"].update({a: v for a, v in prev["nonces"].items() if v["wallet"] == pk})

        t = w["token_accounts"]
        snap["coverage"][f"tokens:{pk}"] = t["status"]
        pstat = t.get("program_status", {})
        for it in t["items"]:
            snap["tokens"][it["account"]] = {
                "wallet": pk,
                "program": it["program"],
                "mint": it["mint"],
                "delegate": it["delegate"],
                "delegated_amount": it["delegated_amount"],
                "close_authority": it["close_authority"],
                "state": it["state"],
                # NFT-lock classification inputs, so watch mode grades a lock exactly as scan does (K3 review).
                "amount": it.get("amount"),
                "decimals": it.get("decimals"),
                "mint_checked": it.get("mint_checked"),
                "mint_supply": it.get("mint_supply"),
                "mint_freeze_authority": it.get("mint_freeze_authority"),
            }
        for a, v in prev["tokens"].items():
            if v["wallet"] == pk and pstat.get(v["program"]) != "ok":
                snap["tokens"].setdefault(a, v)

        if t.get("permanent_delegates_status") == "ok":
            for pd in t.get("permanent_delegates", []):
                snap["perm"][f"{pk}:{pd['mint']}"] = pd["delegate"]
        else:
            snap["perm"].update({k: v for k, v in prev["perm"].items() if k.startswith(pk + ":")})

    for m in report["mints"]:
        snap["coverage"][f"mint:{m['mint']}"] = m["status"]
        if m["status"] in ("ok", "missing", "not_a_mint"):
            snap["mints"][m["mint"]] = {"status": m["status"], **{f: m.get(f) for f in MINT_FIELDS}}
        elif m["mint"] in prev["mints"]:
            snap["mints"][m["mint"]] = prev["mints"][m["mint"]]
    for p in report["programs"]:
        snap["coverage"][f"program:{p['program']}"] = p["status"]
        if p["status"] in ("ok", "missing", "not_a_program"):
            snap["programs"][p["program"]] = {
                "status": p["status"],
                "upgrade_authority": p.get("upgrade_authority"),
                "last_deploy_slot": p.get("last_deploy_slot"),
            }
        elif p["program"] in prev["programs"]:
            snap["programs"][p["program"]] = prev["programs"][p["program"]]
    return snap


def _amount(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def diff(old, new, labels=None):
    """Return a list of alert dicts. `old=None` means first run: every standing risk is reported."""
    labels = labels or {}
    baseline = old is None
    old = normalize(old) or empty_snapshot()
    new = normalize(new)
    alerts = []

    def lab(pk):
        return labels.get(pk) or pk

    def add(sev, kind, subject, detail, wallet=None, before=None, after=None):
        a = {"severity": sev, "kind": kind, "subject": subject, "detail": detail}
        if wallet:
            a["wallet"] = lab(wallet)
        if before is not None or after is not None:
            a["before"], a["after"] = before, after
        if baseline:
            a["baseline"] = True
        alerts.append(a)

    # Squads multisig configuration.
    for addr, v in new["multisigs"].items():
        o = old["multisigs"].get(addr)
        if o is None:
            if baseline:
                add("info", "multisig_baseline", addr,
                    f"{v['threshold']}-of-{len(v['members'])}, time_lock={v['time_lock']}s, config_authority={v['config_authority']}")
            continue
        for k in sorted(set(v["members"]) - set(o["members"])):
            add("critical", "multisig_member_added", addr, f"member {k} added (permissions {v['members'][k]})", None, None, k)
        for k in sorted(set(o["members"]) - set(v["members"])):
            add("critical", "multisig_member_removed", addr, f"member {k} removed", None, k, None)
        for k in sorted(set(o["members"]) & set(v["members"])):
            if o["members"][k] != v["members"][k]:
                add("high", "multisig_permissions_changed", addr, f"permissions of member {k} changed", None, o["members"][k], v["members"][k])
        if o["threshold"] != v["threshold"]:
            add("critical", "multisig_threshold_changed", addr, "approval threshold changed", None, o["threshold"], v["threshold"])
        if o["config_authority"] != v["config_authority"]:
            add("critical", "multisig_config_authority_changed", addr, "config authority changed", None, o["config_authority"], v["config_authority"])
        if o["time_lock"] != v["time_lock"]:
            add("high", "multisig_time_lock_changed", addr, "time lock changed", None, o["time_lock"], v["time_lock"])

    # Durable nonces.
    for acct, v in new["nonces"].items():
        o = old["nonces"].get(acct)
        pv = v.get("provenance") or {}
        opv = (o or {}).get("provenance") or {}
        if pv.get("status") == "ok" and pv.get("creator") == "outside" and not (
            opv.get("status") == "ok" and opv.get("creator") == "outside"
        ):
            add("high", "nonce_outside_creator", acct, outside_creator_text(pv), v["wallet"])
        elif pv.get("status") == "ok" and pv.get("creator") == "watched" and pv.get("fee_payer_outside") and not (
            opv.get("status") == "ok" and opv.get("fee_payer_outside")
        ):
            add("medium", "nonce_outside_fee_payer", acct, outside_fee_payer_text(pv), v["wallet"])
        if o is None:
            who = ""
            if pv.get("status") == "ok":
                who = (f" Funded by {'an OUTSIDE key' if pv['creator'] == 'outside' else 'watched key'} {pv.get('funder')} "
                       f"at {pv.get('created_at')}.")
            elif pv:
                who = " Creator UNKNOWN (provenance " + pv.get("status", "?") + ")."
            add("high" if baseline else "critical", "existing_nonce_account" if baseline else "new_nonce_account", acct,
                f"durable nonce account with authority {v['authority']}. Pre-signed transactions using it never expire "
                "until the nonce advances. Verify you created it." + who, v["wallet"])
            continue
        if o["authority"] != v["authority"]:
            add("critical", "nonce_authority_changed", acct, "nonce authority moved between watched keys", v["wallet"], o["authority"], v["authority"])
        if o["nonce"] != v["nonce"]:
            add("high", "nonce_advanced", acct,
                "nonce value changed: a durable-nonce transaction was executed or the nonce was advanced. Confirm it was yours.",
                v["wallet"], o["nonce"], v["nonce"])
    for acct, o in old["nonces"].items():
        if acct not in new["nonces"]:
            add("info", "nonce_account_gone", acct, "nonce account closed or its authority moved off the watched keys", o["wallet"])

    # Token delegates / close authorities / freezes.
    for acct, v in new["tokens"].items():
        o = old["tokens"].get(acct) or {"delegate": None, "delegated_amount": None, "close_authority": None, "state": None}
        lock_now = bool(v["delegate"]) and is_nft_lock(v)
        if v["delegate"] and v["delegate"] != o["delegate"] and lock_now:
            # Verified frozen 1-of-1 lock: same grading as scan's nft_lock_delegate (info if unthawable, else medium).
            kind = "existing_nft_lock_delegate" if baseline else "new_nft_lock_delegate"
            add(lock_severity(v), kind, acct,
                f"frozen 1-of-1 NFT (mint {v['mint']}) delegated to {v['delegate']}: typical staking/marketplace lock",
                v["wallet"], o["delegate"], v["delegate"])
        elif v["delegate"] and v["delegate"] == o["delegate"] and not lock_now and o.get("mint_checked") and is_nft_lock(o):
            add("high", "nft_lock_released", acct,
                f"delegate {v['delegate']} on mint {v['mint']} is no longer held by a verified frozen lock: it can now act",
                v["wallet"])
        elif v["delegate"] and v["delegate"] != o["delegate"]:
            kind = "existing_delegate" if baseline else ("new_delegate" if not o["delegate"] else "delegate_changed")
            add("high", kind, acct, f"delegate {v['delegate']} approved for {v['delegated_amount']} base units of mint {v['mint']}",
                v["wallet"], o["delegate"], v["delegate"])
        elif v["delegate"] and v["delegate"] == o["delegate"] and v["delegated_amount"] != o["delegated_amount"]:
            up = _amount(v["delegated_amount"]) > _amount(o["delegated_amount"])
            add("high" if up else "medium", "delegate_allowance_increased" if up else "delegate_allowance_decreased", acct,
                f"delegate {v['delegate']} allowance on mint {v['mint']} changed" + ("" if up else " (tokens may have been moved by the delegate)"),
                v["wallet"], o["delegated_amount"], v["delegated_amount"])
        elif not v["delegate"] and o["delegate"]:
            add("info", "delegate_revoked", acct, f"delegate {o['delegate']} removed", v["wallet"], o["delegate"], None)
        if v["close_authority"] and v["close_authority"] != v["wallet"] and v["close_authority"] != o["close_authority"]:
            add("medium", "close_authority_set", acct, f"close authority {v['close_authority']} on mint {v['mint']}", v["wallet"], o["close_authority"], v["close_authority"])
        if v["state"] == "frozen" and o["state"] != "frozen":
            add("info" if lock_now else "medium", "token_account_frozen", acct, f"token account for mint {v['mint']} is frozen", v["wallet"])
    for acct, o in old["tokens"].items():
        if acct not in new["tokens"] and o["delegate"]:
            add("info", "delegate_revoked", acct, f"delegate {o['delegate']} removed (or account closed)", o["wallet"], o["delegate"], None)

    for key, d in new["perm"].items():
        if old["perm"].get(key) != d:
            wallet, mint = key.split(":", 1)
            add("medium", "mint_permanent_delegate", mint,
                f"Token-2022 permanent delegate {d} can move this wallet's balance", wallet, old["perm"].get(key), d)

    # Authorities on watched mints / programs.
    for mint, v in new["mints"].items():
        o = old["mints"].get(mint)
        if o is None:
            if baseline:
                add("info", "mint_baseline", mint, ", ".join(f"{f}={v.get(f)}" for f in MINT_FIELDS[:3]))
            continue
        for f in MINT_FIELDS:
            if o.get(f) != v.get(f):
                add("critical", f"{f}_changed", mint, f"{f.replace('_', ' ')} changed on watched mint", None, o.get(f), v.get(f))
        if o["status"] != v["status"]:
            add("high", "mint_status_changed", mint, "watched mint account status changed", None, o["status"], v["status"])
    for prog, v in new["programs"].items():
        o = old["programs"].get(prog)
        if o is None:
            if baseline:
                add("info", "program_baseline", prog, f"upgrade_authority={v['upgrade_authority']} last_deploy_slot={v['last_deploy_slot']}")
            continue
        if o["upgrade_authority"] != v["upgrade_authority"]:
            add("critical", "upgrade_authority_changed", prog, "program upgrade authority changed", None, o["upgrade_authority"], v["upgrade_authority"])
        if o["last_deploy_slot"] != v["last_deploy_slot"]:
            add("high", "program_redeployed", prog, "program bytecode was redeployed", None, o["last_deploy_slot"], v["last_deploy_slot"])
        if o["status"] != v["status"]:
            add("high", "program_status_changed", prog, "watched program account status changed", None, o["status"], v["status"])

    # Coverage: say loudly when we stop being able to see something.
    for key, st in new["coverage"].items():
        before = old["coverage"].get(key)
        ok_now = st in COVERAGE_OK
        ok_before = before is None or before in COVERAGE_OK
        if not ok_now and (ok_before or baseline):
            add("warn", "coverage_lost", key, f"check is {st}; last known values are being held, changes are NOT being detected", None, before, st)
        elif ok_now and before is not None and not ok_before:
            add("info", "coverage_restored", key, "check is running again", None, before, st)
    order = {"critical": 0, "high": 1, "warn": 2, "medium": 3, "info": 4}
    alerts.sort(key=lambda a: (order.get(a["severity"], 9), a["kind"], a["subject"]))
    return alerts
