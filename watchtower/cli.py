"""watchtower CLI.

  watchtower scan [<pubkey>...] [--squads MULTISIG]... [--mint M]... [--program P]... [--rpc URL] [--json]
                  [--no-provenance]
  watchtower watch --config wallets.toml [--interval 300] [--webhook URL] [--once] [--json]
  watchtower stream --config wallets.toml [--resync-interval 300] [--json]
  watchtower alert-test --config wallets.toml

Exit codes for `scan` (bit flags): 0 clean and complete; 1 risky findings;
2 incomplete coverage (some check could not run); 3 both; 64 usage error.
"""

import argparse
import urllib.parse
import contextlib
import io
import datetime as _dt
import json
import os
import signal
import sys
import time

from . import __version__
from .alerts import emit_stdout, post_webhook
from .base58 import is_pubkey
from .config import DEFAULT_DEDUP_SECONDS, REFERENCE_RPC_ENV_VAR, ConfigError, load_config, load_state, resolve_rpc, save_state
from .diff import COVERAGE_OK, diff, known_provenance, snapshot, squads_fallback
from .redact import exc_text, register_url, scrub, scrub_obj
from .notify import SinkConfigError, WebhookSink, build_sinks, deliver_all, deliver_direct
from .rpc import (DEFAULT_MAX_BLOCK_AGE, DEFAULT_MAX_SLOT_LAG, DEFAULT_RPC, RPC_ENV_VAR, FreshnessGuard, RpcClient, redact_url,
                  validate_http_url)
from .scan import confirm_missing_nonces, run_scan
from .stream import ORDER, StreamWatcher
from .ws import connect as ws_connect
from .ws import derive_ws_url, validate_ws_url

RISKY = {"critical", "high", "medium"}


def _err(msg):
    print(f"watchtower: {scrub(msg)}", file=sys.stderr)


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
    if args.max_slot_lag < 0:
        _err("--max-slot-lag must be >= 0")
        return 64
    if args.max_block_age <= 0:
        _err("--max-block-age must be > 0")
        return 64
    client = _client(args.rpc)
    report = run_scan(client, [{"pubkey": p, "label": ""} for p in dict.fromkeys(args.pubkeys)], args.mint, args.program,
                      squads=args.squads, provenance=not args.no_provenance, max_slot_lag=args.max_slot_lag,
                      max_block_age=args.max_block_age, reference_client=_reference_client(REFERENCE_RPC_ENV_VAR))
    for ms in report["multisigs"]:
        if ms["status"] != "ok":
            _err(f"Squads multisig {ms['address']}: {ms['status'].upper()}: {ms.get('error')}")
    if args.json:
        json.dump(scrub_obj(report), sys.stdout, indent=1)
        print()
    else:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_human(report)
        sys.stdout.write(scrub(buf.getvalue()))
    code = 0
    if any(f["severity"] in RISKY for f in report["findings"]):
        code |= 1
    if not report["complete"]:
        code |= 2
    return code


def watch_cycle(cfg, client, state_path, webhook, as_json=False, out=None, sinks=None, extra_coverage=None,
                after_snapshot=None, result=None):
    """One scan -> diff -> alert -> deliver -> persist cycle. Returns the alerts.

    `sinks` are native alert sinks (notify.py); `webhook` (a URL) adds the generic JSON webhook.
    Streaming mode passes `extra_coverage` (stream health), `after_snapshot(snap, report) -> [alerts]`
    (gap and live-sighting alerts) and `result` (filled with snap and delivery failures).
    """
    prev = load_state(state_path)
    prev_snap = prev["snapshot"] if prev else None
    fresh = {"max_slot_lag": cfg.get("max_slot_lag", DEFAULT_MAX_SLOT_LAG),
             "max_block_age": cfg.get("max_block_age", DEFAULT_MAX_BLOCK_AGE),
             "reference_client": cfg.get("reference_client")}
    report = run_scan(client, cfg["wallets"], cfg["mints"], cfg["programs"], squads=cfg.get("squads", []),
                      known_provenance=known_provenance(prev_snap), squads_fallback=squads_fallback(prev_snap), **fresh)
    snap = snapshot(report, prev_snap)
    # The confirming read gets the same freshness check: a lagging node saying "gone" proves nothing.
    carried = confirm_missing_nonces(
        FreshnessGuard(client, fresh["max_slot_lag"], fresh["max_block_age"], fresh["reference_client"]), prev_snap, snap)
    if carried:
        _err(f"{len(carried)} nonce account(s) missing from the scan still exist on-chain: the RPC answer was incomplete, "
             f"nonce coverage marked UNVERIFIED: {', '.join(carried)}")
    snap["coverage"].update(extra_coverage or {})
    labels = {w["pubkey"]: w["label"] for w in report["wallets"] if w["label"]}
    alerts = diff(prev_snap, snap, labels)
    if after_snapshot:
        extra = after_snapshot(snap, report)
        for a in extra:
            if a.get("wallet"):
                a["wallet"] = labels.get(a["wallet"]) or a["wallet"]
        alerts = sorted(alerts + extra, key=lambda a: (ORDER.get(a["severity"], 9), a["kind"], a["subject"]))
    stamp = report["scanned_at"]
    for a in alerts:
        a["at"] = stamp
    emit_stdout(alerts, as_json=as_json, stream=out)
    blind = [k for k, v in snap["coverage"].items() if v not in COVERAGE_OK]
    _err(f"cycle {stamp}: {len(alerts)} alert(s), {len(snap['coverage']) - len(blind)}/{len(snap['coverage'])} checks running")
    if blind:
        _err(f"{len(blind)} check(s) not running this cycle (changes there are NOT detected): {', '.join(blind)}")

    state = {"tool": "nonce-watchtower", "version": __version__, "updated_at": stamp, "snapshot": snap}
    for k, v in (prev or {}).items():
        if k.startswith("pending_") or k == "delivered":
            state[k] = v
    sinks = list(sinks or [])
    if webhook:
        # Looked up at call time so tests (and embedders) can replace cli.post_webhook.
        sinks.insert(0, WebhookSink(webhook, post=lambda url, al: post_webhook(url, al)))
    failures, notes, held = deliver_all(sinks, alerts, state, stamp, cfg.get("alert_dedup_seconds", DEFAULT_DEDUP_SECONDS))
    for n in notes:
        _err(n)
    for f in failures:
        _err(f"ALERT DELIVERY FAILED: {f}")
    save_state(state_path, state)
    if result is not None:
        result.update(snap=snap, report=report, delivery_failures=failures, held=held)
    return alerts


def _load_watch_config(args):
    cfg = load_config(args.config)
    if args.max_slot_lag is not None:
        if args.max_slot_lag < 0:
            raise ConfigError("--max-slot-lag must be >= 0")
        cfg["max_slot_lag"] = args.max_slot_lag
    if args.max_block_age is not None:
        if args.max_block_age <= 0:
            raise ConfigError("--max-block-age must be > 0")
        cfg["max_block_age"] = args.max_block_age
    cfg["reference_client"] = _reference_client(cfg["reference_rpc_url_env"])
    client = _client(args.rpc, cfg["rpc_url_env"])
    webhook = args.webhook or os.environ.get(cfg["webhook_url_env"])
    sinks = build_sinks(cfg, os.environ)
    return cfg, client, webhook, sinks


def _reference_client(env_name):
    """Optional independent RPC used only as a slot reference (its URL is a credential: registered, redacted)."""
    url = os.environ.get(env_name)
    if not url:
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    validate_http_url(url, "reference RPC URL", allow_http=host in ("localhost", "127.0.0.1", "::1"))
    return RpcClient(url)


def _sink_names(webhook, sinks):
    names = (["webhook"] if webhook else []) + [s.name for s in sinks]
    return ", ".join(names) if names else "stdout only"


def cmd_watch(args):
    if args.interval < 30:
        _err("--interval must be at least 30 seconds")
        return 64
    try:
        cfg, client, webhook, sinks = _load_watch_config(args)
    except (ConfigError, SinkConfigError) as e:
        _err(str(e))
        return 64
    state_path = args.state or cfg["state_file"]
    _err(f"watching {len(cfg['wallets'])} wallet(s), {len(cfg['mints'])} mint(s), {len(cfg['programs'])} program(s) "
         f"via {client.display}; state={state_path}; alerts: {_sink_names(webhook, sinks)}")
    if client.url == DEFAULT_RPC:
        _err(f"using the public RPC; set ${cfg['rpc_url_env']} to a provider for reliable nonce coverage")
    failure = None  # {"alert", "missing": sink names} while cycles keep failing
    all_sinks = ([WebhookSink(webhook)] if webhook else []) + sinks
    while True:
        res = {}
        try:
            watch_cycle(cfg, client, state_path, webhook, as_json=args.json, sinks=sinks, result=res)
            if failure is not None:
                _err(f"cycle recovered after failing since {failure['alert']['at']}")
                failure = None
        except KeyboardInterrupt:
            return 0
        except Exception as e:  # keep watching, but a failed cycle is a coverage gap and goes to the sinks
            # (_report_cycle_failure scrubs: the exception text may contain an RPC/webhook URL or a token)
            failure = _report_cycle_failure(e, failure, all_sinks, args.json)
            if args.once:
                return 2
        if args.once:
            # A timer unit must show as failed when alerts did not reach a configured sink, including
            # alerts held back by the per-cycle message cap: a one-shot run has no "next cycle" of its own.
            for name, n in sorted((res.get("held") or {}).items()):
                _err(f"ALERTS NOT YET DELIVERED: {n} alert(s) still queued for {name} (message cap); they go out on "
                     "the next run")
            return 2 if res.get("delivery_failures") or res.get("held") else 0
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0


def _report_cycle_failure(exc, failure, sinks, as_json):
    """A failed cycle is alerted on stdout and straight to every sink (no queue, no state: those may be what
    failed), on every failed cycle while it lasts. Sinks that miss an alert get the latest one on the next try."""
    err = exc_text(exc)
    _err(f"cycle FAILED: {err}")
    # `watch` retries exactly once per --interval, so every failed cycle raises a fresh scan_failed: delivered
    # alerts are never further apart than one interval, and a long outage is never a single alert.
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
    since = failure["since"] if failure else now
    alert = {"severity": "high", "kind": "scan_failed", "subject": "watch", "at": now, "before": since, "after": now,
             "detail": (f"the scan/alert/state cycle FAILED ({err}). " if failure is None else
                        f"the scan/alert/state cycle is STILL FAILING (latest: {err}). ")
                       + f"Changes are NOT being detected, delivered or recorded until a cycle succeeds. "
                         f"Coverage gap since {since}."}
    emit_stdout([alert], as_json=as_json)
    failure = {"alert": alert, "missing": {s.name for s in sinks}, "since": since}
    res = deliver_direct([s for s in sinks if s.name in failure["missing"]], [failure["alert"]], failure["alert"]["at"])
    for name, (ok, msg) in res.items():
        if ok:
            failure["missing"].discard(name)
        else:
            _err(f"ALERT DELIVERY FAILED: scan_failed alert did not reach {name} ({msg}); retrying")
    return failure


def cmd_stream(args):
    if args.resync_interval < 30:
        _err("--resync-interval must be at least 30 seconds")
        return 64
    if args.min_gap < 2:
        _err("--min-gap must be at least 2 seconds")
        return 64
    try:
        cfg, client, webhook, sinks = _load_watch_config(args)
        ws_url = os.environ.get(cfg["ws_url_env"]) or derive_ws_url(client.url)
        register_url(ws_url)
        validate_ws_url(ws_url)
    except (ConfigError, SinkConfigError, ValueError) as e:
        _err(str(e))
        return 64
    if webhook:
        sinks.insert(0, WebhookSink(webhook))
    state_path = args.state or cfg["state_file"]
    _err(f"streaming {len(cfg['wallets'])} wallet(s), {len(cfg['squads'])} multisig(s), {len(cfg['mints'])} mint(s), "
         f"{len(cfg['programs'])} program(s); rpc {client.display}; pubsub {redact_url(ws_url)}; full re-sync every "
         f"{args.resync_interval}s; state={state_path}; alerts: {_sink_names(None, sinks)}")
    if client.url == DEFAULT_RPC:
        _err(f"using the public RPC; set ${cfg['rpc_url_env']} (and ${cfg['ws_url_env']}) to a provider for reliable coverage")

    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    watcher = StreamWatcher(cfg, client, state_path, ws_url, cycle=watch_cycle, connect=ws_connect, sinks=sinks,
                            as_json=args.json, resync_interval=float(args.resync_interval), min_gap=float(args.min_gap),
                            prev_state=load_state(state_path))
    try:
        return watcher.run()
    except KeyboardInterrupt:
        _err("stream: stopped")
        return 0


def cmd_alert_test(args):
    try:
        cfg = load_config(args.config)
        sinks = build_sinks(cfg, os.environ, webhook=os.environ.get(cfg["webhook_url_env"]))
    except (ConfigError, SinkConfigError) as e:
        _err(str(e))
        return 64
    if not sinks:
        _err("no alert sink is configured (set the Telegram, Discord or webhook environment variables)")
        return 64
    stamp = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
    probe = [{"severity": "info", "kind": "alert_test", "subject": "nonce-watchtower", "at": stamp,
              "detail": "test message: if you can read this, alerts reach this channel"}]
    code = 0
    for s in sinks:
        ok, msg, _ = s.deliver(probe, stamp)
        print(scrub(f"{s.name}: {'OK' if ok else 'FAILED'} ({msg})"))
        code = code if ok else 2
    return code


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
    s.add_argument("--max-slot-lag", type=int, default=DEFAULT_MAX_SLOT_LAG, metavar="SLOTS", help="treat a nonce/account answer more than this many slots behind the endpoint's finalized slot as stale (a coverage gap); default %(default)s")
    s.add_argument("--max-block-age", type=int, default=DEFAULT_MAX_BLOCK_AGE, metavar="SECONDS",
                    help="treat the endpoint as stale when its finalized slot is older than this by its "
                         "block time (a node behind the chain); default %(default)s")
    s.add_argument("--json", action="store_true", help="machine-readable report")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="poll, diff against local state, alert on changes")
    w.add_argument("--config", required=True, help="wallets.toml")
    w.add_argument("--interval", type=int, default=300, help="seconds between scans (min 30)")
    w.add_argument("--webhook", help="https webhook URL (default: $WATCHTOWER_WEBHOOK_URL)")
    w.add_argument("--rpc", help=f"RPC URL (default: env var named in config, else {DEFAULT_RPC})")
    w.add_argument("--max-slot-lag", type=int, default=None, metavar="SLOTS", help="treat a nonce/account answer more than this many slots behind the endpoint's finalized slot as stale (a coverage gap); default: max_slot_lag in the config, else 64")
    w.add_argument("--max-block-age", type=int, default=None, metavar="SECONDS",
                    help="treat the endpoint as stale when its finalized slot is older than this by its "
                         "block time (a node behind the chain); default: max_block_age in the config, else 120")
    w.add_argument("--state", help="state file path (default: next to the config)")
    w.add_argument("--once", action="store_true", help="run a single cycle and exit (for cron/systemd timers)")
    w.add_argument("--json", action="store_true", help="alerts as JSON lines")
    w.set_defaults(func=cmd_watch)

    st = sub.add_parser("stream", help="live WebSocket subscriptions + periodic full re-sync; alerts on changes")
    st.add_argument("--config", required=True, help="wallets.toml")
    st.add_argument("--resync-interval", type=int, default=300,
                    help="seconds between full re-sync scans while connected; also the polling interval while the "
                         "stream is down (min 30)")
    st.add_argument("--min-gap", type=int, default=10,
                    help="minimum seconds between notification-triggered scans; notifications in between are "
                         "coalesced into the next scan (min 2)")
    st.add_argument("--webhook", help="https webhook URL (default: $WATCHTOWER_WEBHOOK_URL)")
    st.add_argument("--rpc", help=f"RPC URL (default: env var named in config, else {DEFAULT_RPC})")
    st.add_argument("--max-slot-lag", type=int, default=None, metavar="SLOTS", help="treat a nonce/account answer more than this many slots behind the endpoint's finalized slot as stale (a coverage gap); default: max_slot_lag in the config, else 64")
    st.add_argument("--max-block-age", type=int, default=None, metavar="SECONDS",
                    help="treat the endpoint as stale when its finalized slot is older than this by its "
                         "block time (a node behind the chain); default: max_block_age in the config, else 120")
    st.add_argument("--state", help="state file path (default: next to the config)")
    st.add_argument("--json", action="store_true", help="alerts as JSON lines")
    st.set_defaults(func=cmd_stream)

    at = sub.add_parser("alert-test", help="send one test message to every configured alert sink")
    at.add_argument("--config", required=True, help="wallets.toml")
    at.set_defaults(func=cmd_alert_test)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        _err(str(e))
        return 64
    except KeyboardInterrupt:
        return 0
    except Exception as e:  # never let a traceback print an unscrubbed secret
        _err(f"internal error: {exc_text(e)}")
        return 70


if __name__ == "__main__":
    sys.exit(main())
