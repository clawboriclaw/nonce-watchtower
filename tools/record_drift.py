#!/usr/bin/env python3
"""Record the public on-chain data behind tests/test_drift_replay.py (read-only, stdlib only).

  python tools/record_drift.py [--rpc URL] [--out tests/fixtures/drift]

Uses the project's own read-only RPC client (only allowlisted read methods can be called). Writes the JSON-RPC
responses verbatim, one file per call, so the replay test can run offline in CI. See tests/fixtures/drift/README.md
for what is recorded and what the test reconstructs from it.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from watchtower.rpc import DEFAULT_RPC, RpcClient  # noqa: E402

# The two durable-nonce accounts the Drift attack transactions advanced (their authorities are two
# Security Council signer keys), and the two attack transactions.
NONCES = [
    "7s7s6saC5LHZoLyBXLM3pCjpWaA7meyQdP8NiH9ktAeC",
    "EmYEryTDXtuVCxrjNqJXbiwr4hfiJajd4g5P58vvhQnc",
]
ATTACK_TXS = [
    "2HvMSgDEfKhNryYZKhjowrBY55rUx5MWtcWkG9hqxZCFBaTiahPwfynP1dxBSRk9s5UTVc8LFeS4Btvkm9pc2C4H",
    "4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1",
]
TX_OPTS = {"encoding": "json", "maxSupportedTransactionVersion": 0, "commitment": "finalized"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc", default=os.environ.get("WATCHTOWER_RPC_URL") or DEFAULT_RPC)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "drift"))
    args = ap.parse_args()
    client = RpcClient(args.rpc)
    os.makedirs(args.out, exist_ok=True)

    def save(name, method, params):
        result = client.call(method, params)
        with open(os.path.join(args.out, name), "w") as f:
            json.dump({"jsonrpc": "2.0", "id": 1, "result": result}, f, indent=1, sort_keys=True)
            f.write("\n")
        time.sleep(0.5)  # be polite to the public endpoint
        return result

    sigs = set(ATTACK_TXS)
    for acct in NONCES:
        page = save(f"sigs_{acct}.json", "getSignaturesForAddress", [acct, {"limit": 1000, "commitment": "finalized"}])
        if not page:
            sys.exit(f"{acct}: no history returned (pruned or not indexed on this RPC)")
        if len(page) >= 1000:
            sys.exit(f"{acct}: history longer than one page; extend the recorder before trusting it")
        # Walk past the oldest signature: an empty next page shows the history is complete, not just short.
        older = client.call("getSignaturesForAddress", [acct, {"limit": 1000, "before": page[-1]["signature"],
                                                               "commitment": "finalized"}])
        if older:
            sys.exit(f"{acct}: {len(older)} signature(s) older than the first page; history is not complete")
        sigs.update(rec["signature"] for rec in page)
        save(f"account_{acct}.json", "getAccountInfo", [acct, {"encoding": "base64", "commitment": "finalized"}])
    if len({s[:8] for s in sigs}) != len(sigs):
        sys.exit("two signatures share an 8-character prefix; fixture file names would collide")
    for sig in sorted(sigs):
        tx = save(f"tx_{sig[:8]}.json", "getTransaction", [sig, TX_OPTS])
        if not tx:
            sys.exit(f"{sig}: not returned by this RPC (pruned?)")
    print(f"recorded {len(NONCES)} nonce accounts and {len(sigs)} transactions into {os.path.normpath(args.out)}")


if __name__ == "__main__":
    main()
