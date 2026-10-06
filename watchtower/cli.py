"""watchtower CLI.

  watchtower scan [<pubkey>...] [--squads MULTISIG]... [--mint M]... [--program P]... [--rpc URL] [--json]
                  [--no-provenance]
  watchtower watch --config wallets.toml [--interval 300] [--webhook URL] [--once] [--json]

Exit codes for `scan` (bit flags): 0 clean and complete; 1 risky findings;
2 incomplete coverage (some check could not run); 3 both; 64 usage error.
"""

import argparse
import datetime as _dt
import json
import os
import sys
import time

from . import __version__
from .alerts import emit_stdout, post_webhook
from .base58 import is_pubkey
from .config import ConfigError, load_config, load_state, resolve_rpc, save_state
from .diff import COVERAGE_OK, diff, known_provenance, snapshot, squads_fallback
from .rpc import DEFAULT_RPC, RPC_ENV_VAR, RpcClient
from .scan import run_scan

RISKY = {"critical", "high", "medium"}
MAX_PENDING = 500


def _err(msg):
    print(f"watchtower: {msg}", file=sys.stderr)


def _client(cli_rpc, env_name=RPC_ENV_VAR):
    url = resolve_rpc(cli_rpc, env_name)
    if cli_rpc and ("?" in cli_rpc or "api-key" in cli_rpc.lower() or "api_key" in cli_rpc.lower()):
        _err(f"note: an RPC URL with a key on the command line ends up in shell history; prefer ${env_name}")
    return RpcClient(url)


def print_human(report):
    print(f"nonce-watchtower {report['version']}  rpc={report['rpc']}  at={report['scanned_at']}")
    for ms in report.get("multisigs", []):
        print(f"\nsquads multisig {ms['address']}: {ms['status']}" + (f" ({ms.get('error')})" if ms["status"] != "ok" else ""))
        if ms["status"] == "ok":
            print(f"  {ms['threshold']}-of-{len(ms['members'])}  time_lock={ms['time_lock']}s  "
                  f"config_authority={ms.get('config_authority')}  transaction_index={ms['transaction_index']}")
        for k in ms.get("watched_keys", []):
            print(f"  watching {k['pubkey']}  {k['role']}")
    cov = report["nonce_coverage"]
    print(f"nonce coverage: {cov['status']}" + (f" ({cov.get('error')})" if cov["status"] != "ok" and cov["status"] != "skipped" else ""))
    for w in report["wallets"]:
        n, t = w["nonces"], w["token_accounts"]
        name = f"{w['label']} " if w["label"] else ""
        print(f"\nwallet {name}{w['pubkey']}")
        print(f"  durable nonce accounts (authority = this key): {n['status']}, {len(n.get('items', []))} found")
        for it in n.get("items", []):
            print(f"    {it['account']}  nonce={it['nonce']}  {it['version']}")
            pv = it.get("provenance")
            if pv and pv["status"] == "ok":
                print(f"      created {pv['created_at']}  creator={pv['creator'].upper() if pv['creator'] == 'outside' else 'watched'}  "
                      f"funder={pv['funder']}  initial_authority={pv.get('initial_authority')}  fee_payer={pv['fee_payer']}"
                      f"{' (OUTSIDE)' if pv.get('fee_payer_outside') else ''}  sig {pv['signature']}")
            elif pv:
                print(f"      provenance {pv['status']}: {pv.get('error')}")
        print(f"  token accounts with delegate/close-authority/frozen: {t['status']}, {len(t['items'])} found")
        for it in t["items"]:
            print(f"    {it['account']}  mint={it['mint']}  delegate={it['delegate']}  amount={it['delegated_amount']}  close={it['close_authority']}  state={it['state']}")
        for pd in t.get("permanent_delegates", []):
            print(f"    permanent delegate on held Token-2022 mint {pd['mint']}: {pd['delegate']}")
    for m in report["mints"]:
        print(f"\nmint {m['mint']}: {m['status']}  mint_authority={m.get('mint_authority')}  freeze_authority={m.get('freeze_authority')}  permanent_delegate={m.get('permanent_delegate')}  held_by_watched={m.get('held_by_watched')}")
    for p in report["programs"]:
        print(f"\nprogram {p['program']}: {p['status']}  upgrade_authority={p.get('upgrade_authority')}  last_deploy_slot={p.get('last_deploy_slot')}  held_by_watched={p.get('held_by_watched')}")
    risky = [f for f in report["findings"] if f["severity"] in RISKY | {"warn"}]
    print(f"\nfindings: {len(risky)} needing attention, complete={report['complete']}")
    emit_stdout(risky)
    advice = cov.get("advice") or next((w["nonces"].get("advice") for w in report["wallets"] if w["nonces"].get("advice")), None)
    if advice:
        print(f"\nADVICE: {advice}")


def cmd_scan(args):
    bad = [k for k in args.pubkeys + args.mint + args.program + args.squads if not is_pubkey(k)]
    if bad:
        _err(f"invalid public key(s): {', '.join(bad)}")
        return 64
    if not (args.pubkeys or args.mint or args.program or args.squads):
        _err("nothing to scan")
        return 64
    client = _client(args.rpc)
    report = run_scan(client, [{"pubkey": p, "label": ""} for p in dict.fromkeys(args.pubkeys)], args.mint, args.program,
                      squads=args.squads, provenance=not args.no_provenance)
    for ms in report["multisigs"]:
        if ms["status"] != "ok":
            _err(f"Squads multisig {ms['address']}: {ms['status'].upper()}: {ms.get('error')}")
    if args.json:
        json.dump(report, sys.stdout, indent=1)
        print()
    else:
        print_human(report)
    code = 0
    if any(f["severity"] in RISKY for f in report["findings"]):
        code |= 1
    if not report["complete"]:
        code |= 2
    return code


def watch_cycle(cfg, client, state_path, webhook, as_json=False, out=None):
    """One scan -> diff -> alert -> persist cycle. Returns the alerts."""
    prev = load_state(state_path)
    prev_snap = prev["snapshot"] if prev else None
    report = run_scan(client, cfg["wallets"], cfg["mints"], cfg["programs"], squads=cfg.get("squads", []),
                      known_provenance=known_provenance(prev_snap), squads_fallback=squads_fallback(prev_snap))
    snap = snapshot(report, prev_snap)
    labels = {w["pubkey"]: w["label"] for w in report["wallets"] if w["label"]}
    alerts = diff(prev_snap, snap, labels)
    stamp = report["scanned_at"]
    for a in alerts:
        a["at"] = stamp
    emit_stdout(alerts, as_json=as_json, stream=out)
    blind = [k for k, v in snap["coverage"].items() if v not in COVERAGE_OK]
    _err(f"cycle {stamp}: {len(alerts)} alert(s), {len(snap['coverage']) - len(blind)}/{len(snap['coverage'])} checks running")
    if blind:
        _err(f"{len(blind)} check(s) not running this cycle (changes there are NOT detected): {', '.join(blind)}")

    pending = (prev or {}).get("pending_webhook", [])
    if webhook:
        to_send = pending + alerts
        ok, msg = post_webhook(webhook, to_send)
        if not ok:
            _err(f"{msg}; {len(to_send)} alert(s) queued for retry")
            pending = to_send[-MAX_PENDING:]
        else:
            pending = []
    save_state(
        state_path,
        {"tool": "nonce-watchtower", "version": __version__, "updated_at": stamp, "snapshot": snap, "pending_webhook": pending},
    )
    return alerts


def cmd_watch(args):
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        _err(str(e))
        return 64
    if args.interval < 30:
        _err("--interval must be at least 30 seconds")
        return 64
    client = _client(args.rpc, cfg["rpc_url_env"])
    webhook = args.webhook or os.environ.get(cfg["webhook_url_env"])
    state_path = args.state or cfg["state_file"]
    _err(f"watching {len(cfg['wallets'])} wallet(s), {len(cfg['mints'])} mint(s), {len(cfg['programs'])} program(s) "
         f"via {client.display}; state={state_path}; webhook={'on' if webhook else 'off'}")
    if client.url == DEFAULT_RPC:
        _err(f"using the public RPC; set ${cfg['rpc_url_env']} to a provider for reliable nonce coverage")
    while True:
        try:
            watch_cycle(cfg, client, state_path, webhook, as_json=args.json)
        except KeyboardInterrupt:
            return 0
        except Exception as e:  # keep watching; a crash is a silent blind spot
            _err(f"cycle failed at {_dt.datetime.now(_dt.timezone.utc).isoformat()}: {type(e).__name__}: {e}")
            if args.once:
                return 2
        if args.once:
            return 0
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0


def build_parser():
    p = argparse.ArgumentParser(prog="watchtower", description="Read-only watch on durable nonces, token delegates and authorities for Solana keys.")
    p.add_argument("--version", action="version", version=f"nonce-watchtower {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="one-off read-only scan")
    s.add_argument("pubkeys", nargs="*", help="wallet / multisig-member public keys")
    s.add_argument("--squads", action="append", default=[], metavar="MULTISIG",
                   help="Squads v4 multisig account: watch all its members, vault 0 and config authority (repeatable)")
    s.add_argument("--no-provenance", action="store_true",
                   help="skip the transaction-history lookup of who created each nonce account")
    s.add_argument("--mint", action="append", default=[], help="mint to report authorities for (repeatable)")
    s.add_argument("--program", action="append", default=[], help="program id to report upgrade authority for (repeatable)")
    s.add_argument("--rpc", help=f"RPC URL (default: ${RPC_ENV_VAR} or {DEFAULT_RPC})")
    s.add_argument("--json", action="store_true", help="machine-readable report")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="poll, diff against local state, alert on changes")
    w.add_argument("--config", required=True, help="wallets.toml")
    w.add_argument("--interval", type=int, default=300, help="seconds between scans (min 30)")
    w.add_argument("--webhook", help="https webhook URL (default: $WATCHTOWER_WEBHOOK_URL)")
    w.add_argument("--rpc", help=f"RPC URL (default: env var named in config, else {DEFAULT_RPC})")
    w.add_argument("--state", help="state file path (default: next to the config)")
    w.add_argument("--once", action="store_true", help="run a single cycle and exit (for cron/systemd timers)")
    w.add_argument("--json", action="store_true", help="alerts as JSON lines")
    w.set_defaults(func=cmd_watch)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        _err(str(e))
        return 64


if __name__ == "__main__":
    sys.exit(main())
