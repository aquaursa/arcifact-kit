#!/usr/bin/env python3
"""Append-only run-commitment record.

The threat model states plainly that a static certificate cannot show
that a threshold existed before a run, or that a held-out bank existed
in final form before evaluation. Those are properties of the ISSUANCE
process. This is the record that makes them checkable.

Every entry commits to a fact BEFORE the thing it constrains happens,
and carries the hash of the entry before it. The chain is signed at the
head. Changing or removing any past entry changes every hash after it
and breaks the signature, so the log can be appended to but not
rewritten without detection.

What this does NOT do, stated here so nobody has to infer it:

  - It proves nothing about anything that happened before entry 1. The
    log begins when it begins. Past runs are not retroactively
    strengthened by it, and claiming otherwise would be the exact
    failure this company exists to prevent.
  - The issuer controls the clock. A timestamp in the log is the
    issuer's assertion, not an independent one. What makes it hard to
    backdate is the ANCHOR: each head is published to a public git
    repository, so the head hash appears in a third-party-hosted commit
    with a server-side timestamp. Verification against that anchor is
    external to Arcifact and is what a sceptical reader should check.
  - It says nothing about whether a committed threshold was sensible,
    only that it was fixed in advance.

Usage:
    python3 commit_log.py append --kind bar --subject "gate v1.0.0" \\
        --claim "..." --digest <sha256>
    python3 commit_log.py sign
    python3 commit_log.py show
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "site_pub", "commitments.json")
KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "keys", "issuer_ed25519_private.hex")
KEY_ID = "arcifact-issuer-2026-08"

GENESIS = "0" * 64


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def entry_hash(entry):
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canon(body)).hexdigest()


def load():
    if os.path.exists(LOG):
        return json.load(open(LOG))
    return {"schema": "arcifact-commitments/1",
            "note": ("Append-only. Each entry carries the hash of the "
                     "one before it. The log proves nothing about "
                     "events before entry 1."),
            "anchor": {
                "kind": "public-git",
                "repository": "https://github.com/arcifact/arcifact-site",
                "how_to_check": ("Each head hash below is published in "
                                 "this file, which is committed to a "
                                 "public git repository. Find the commit "
                                 "that introduced a given head and read "
                                 "its server-side timestamp. That "
                                 "timestamp is not under the issuer's "
                                 "control.")},
            "entries": [], "signature": None}


def cmd_append(a):
    log = load()
    prev = (log["entries"][-1]["entry_hash"] if log["entries"] else GENESIS)
    e = {
        "n": len(log["entries"]) + 1,
        "utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": a.kind,
        "subject": a.subject,
        "claim": a.claim,
        "digest": a.digest,
        "prev": prev,
    }
    e["entry_hash"] = entry_hash(e)
    log["entries"].append(e)
    log["signature"] = None            # any append invalidates the seal
    json.dump(log, open(LOG, "w"), indent=1)
    print(f"entry {e['n']} appended  {e['entry_hash'][:16]}  (unsigned)")


def cmd_sign(a):
    log = load()
    if not log["entries"]:
        raise SystemExit("nothing to sign")
    head = log["entries"][-1]["entry_hash"]
    try:
        from nacl.signing import SigningKey
    except ImportError:
        raise SystemExit("pynacl required to sign")
    sk = SigningKey(bytes.fromhex(open(KEY).read().strip()))
    payload = canon({"head": head, "count": len(log["entries"])})
    sig = sk.sign(payload).signature.hex()
    log["signature"] = {"alg": "ed25519", "key_id": KEY_ID,
                        "head": head, "count": len(log["entries"]),
                        "sig": sig}
    json.dump(log, open(LOG, "w"), indent=1)
    print(f"signed head {head[:16]} over {len(log['entries'])} entries")


def cmd_show(a):
    log = load()
    for e in log["entries"]:
        print(f"  {e['n']:3d}  {e['utc']}  {e['kind']:10s} "
              f"{e['subject'][:40]:42s} {e['entry_hash'][:12]}")
    s = log.get("signature")
    print(f"  signature: {'present, head ' + s['head'][:12] if s else 'ABSENT'}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    ap = sub.add_parser("append")
    ap.add_argument("--kind", required=True,
                    choices=["bar", "heldout", "artifact", "policy"])
    ap.add_argument("--subject", required=True)
    ap.add_argument("--claim", required=True)
    ap.add_argument("--digest", default="")
    ap.set_defaults(fn=cmd_append)
    sp = sub.add_parser("sign"); sp.set_defaults(fn=cmd_sign)
    sh = sub.add_parser("show"); sh.set_defaults(fn=cmd_show)
    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
