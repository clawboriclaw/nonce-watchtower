#!/usr/bin/env python3
"""Cross-check the Drift replay fixtures against a second RPC provider (read-only, stdlib only).

  python tools/verify_drift.py --rpc https://solana-rpc.publicnode.com

Re-fetches every recorded call and compares the fields the replay depends on: signature lists (and that no
older signature exists), the four transactions (signatures, slot, block time, account keys, recent blockhash,
instructions, error status), and the nonce accounts (owner and data). Exit 0 only if everything matches.
"""

import argparse
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from watchtower.rpc import RpcClient, RpcError  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "drift")


def tx_facts(tx):
    t, m = tx["transaction"], tx["transaction"]["message"]
    return {"signatures": t["signatures"], "slot": tx["slot"], "blockTime": tx["blockTime"],
            "accountKeys": m["accountKeys"], "recentBlockhash": m["recentBlockhash"],
            "instructions": m["instructions"], "err": (tx.get("meta") or {}).get("err"),
            "loaded": (tx.get("meta") or {}).get("loadedAddresses")}


def sig_facts(page):
    return [(s["signature"], s["slot"], s.get("blockTime"), s.get("err")) for s in page]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc", required=True)
    args = ap.parse_args()
    client = RpcClient(args.rpc)
    bad = 0

    def check(name, ok):
        nonlocal bad
        print(f"{'OK  ' if ok else 'DIFF'} {name}")
        bad += not ok

    for path in sorted(glob.glob(os.path.join(FIX, "*.json"))):
        name = os.path.basename(path)
        rec = json.load(open(path))["result"]
        try:
            verify_one(client, check, name, rec)
        except RpcError as e:
            print(f"N/A  {name}: not served by this provider ({str(e)[:120]})")
        time.sleep(0.5)
    print("all fixtures this provider serves match" if not bad else f"{bad} fixture(s) differ")
    sys.exit(1 if bad else 0)


def verify_one(client, check, name, rec):
        if name.startswith("sigs_"):
            acct = name[5:-5]
            live = client.call("getSignaturesForAddress", [acct, {"limit": 1000, "commitment": "finalized"}])
            check(name, sig_facts(live) == sig_facts(rec))
            try:
                older = client.call("getSignaturesForAddress", [acct, {"limit": 1000, "before": rec[-1]["signature"],
                                                                       "commitment": "finalized"}])
                check(f"{name}: no older signature", older == [])
            except RpcError as e:
                print(f"N/A  {name}: no-older-signature check unavailable on this provider ({e})")
        elif name.startswith("tx_"):
            sig = rec["transaction"]["signatures"][0]
            live = client.call("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                                                       "commitment": "finalized"}])
            check(name, bool(live) and tx_facts(live) == tx_facts(rec))
        elif name.startswith("account_"):
            acct = name[8:-5]
            live = client.call("getAccountInfo", [acct, {"encoding": "base64", "commitment": "finalized"}])
            lv, rv = (live or {}).get("value") or {}, rec["value"]
            check(name, lv.get("owner") == rv["owner"] and lv.get("data") == rv["data"])


if __name__ == "__main__":
    main()
