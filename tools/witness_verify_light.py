#!/usr/bin/env python3
"""Witness light verifier. Checks a Witness certificate against the
workflow file it was issued for, in this order:
  1. the certificate's self-seal: sha256 recomputed over its own
     contents must equal the stored value (tamper-evidence);
  2. the source digest: sha256 of the workflow file must match;
  3. every witness chain, edge by edge, against the file;
  4. every exhibit schedule: it must be a permutation of exactly
     the workflow's jobs, respect every recorded dependency, and
     place the claimed pair in the claimed direction.
No reconstruction of the schedule space is performed; counts are
recomputed only in full-mode verification, available under
evaluation terms. Usage:
  python3 witness_verify_light.py cert.json workflow.yml
Requires: pyyaml. Patents pending GB2618664.3, GB2619009.0."""
import hashlib
import hmac
import json
import sys

import yaml


def sha(x):
    return hashlib.sha256(
        x if isinstance(x, bytes) else x.encode()).hexdigest()


def seal_ok(cert):
    claimed = cert.get("sha256", "")
    body = {k: v for k, v in cert.items() if k != "sha256"}
    computed = sha(json.dumps(body, sort_keys=True))
    return hmac.compare_digest(str(claimed), computed)


def main(cert_path, wf_path):
    cert = json.load(open(cert_path))
    doc = yaml.safe_load(open(wf_path))
    jobs = doc.get("jobs", {})
    jobset = set(jobs)
    edges = set()
    for j, s in jobs.items():
        needs = s.get("needs", []) if isinstance(s, dict) else []
        needs = [needs] if isinstance(needs, str) else needs
        for n in needs:
            if n in jobs:
                edges.add((n, j))

    checks = {}
    checks["seal_match"] = seal_ok(cert)
    checks["source_match"] = (
        sha(open(wf_path, "rb").read()) == cert.get("source_sha"))
    fails = 0
    for a in cert.get("artifacts", []):
        if a["type"] == "verdict" and "witness_chain" in a:
            ch = a["witness_chain"]
            ok = all((ch[i], ch[i + 1]) in edges
                     for i in range(len(ch) - 1))
            end = ((a["a"], a["b"]) if a["verdict"] == "PROVEN_YES"
                   else (a["b"], a["a"]))
            ok = ok and len(ch) >= 2 and (ch[0], ch[-1]) == end
            fails += not ok
        elif a["type"] == "exhibit":
            o = a["order"]
            # exact permutation of the workflow's jobs, not merely
            # the right cardinality of unique names
            ok = set(o) == jobset and len(o) == len(jobset)
            if ok:
                pos = {x: i for i, x in enumerate(o)}
                ok = all(pos[u] < pos[v] for u, v in edges)
                pa, pb = a["a"], a["b"]
                ok = ok and ((pos[pa] < pos[pb])
                             == (a["direction"] == "yes"))
            fails += not ok
    checks["artifact_fails"] = fails
    checks["GREEN"] = (checks["seal_match"]
                       and checks["source_match"]
                       and fails == 0)
    print(json.dumps(checks, indent=1))
    return 0 if checks["GREEN"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
