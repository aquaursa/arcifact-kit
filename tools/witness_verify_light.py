#!/usr/bin/env python3
"""Witness light verifier. Checks a Witness certificate against the
workflow file it was issued for. Light verification establishes
CONSISTENCY, not completeness of counting (full mode recounts the
schedule space under evaluation terms). It checks, in order:
  1. schema: schema tag, required fields, a non-empty artifacts list,
     known artifact types, and a well-formed workflow with no needs
     reference to a nonexistent job;
  2. the certificate self-seal;
  3. the source digest of the workflow file;
  4. every witness chain, edge by edge;
  5. every exhibit schedule: an exact permutation of the workflow's
     jobs, respecting every dependency and the claimed direction.
An empty artifacts list, an unknown artifact type, or a workflow whose
needs reference a job that does not exist all fail. Usage:
  python3 witness_verify_light.py cert.json workflow.yml
Requires: pyyaml. Patents pending GB2618664.3, GB2619009.0."""
import hashlib
import hmac
import json
import sys

import yaml

KNOWN_TYPES = {"verdict", "exhibit", "whatif"}


def sha(x):
    return hashlib.sha256(
        x if isinstance(x, bytes) else x.encode()).hexdigest()


def parse_workflow(doc):
    jobs = doc.get("jobs", {})
    jobset = set(jobs)
    edges = set()
    bad_refs = []
    for j, s in jobs.items():
        needs = s.get("needs", []) if isinstance(s, dict) else []
        needs = [needs] if isinstance(needs, str) else needs
        for n in needs:
            if n in jobs:
                edges.add((n, j))
            else:
                bad_refs.append((j, n))
    return jobset, edges, bad_refs


def main(cert_path, wf_path):
    cert = json.load(open(cert_path))
    doc = yaml.safe_load(open(wf_path))
    jobset, edges, bad_refs = parse_workflow(doc)

    checks = {}
    # ---- schema / completeness ----
    schema_errs = []
    if cert.get("schema") != "witness/1":
        schema_errs.append("schema must be witness/1")
    arts = cert.get("artifacts")
    if not isinstance(arts, list) or len(arts) == 0:
        schema_errs.append("artifacts must be a non-empty list")
    else:
        for a in arts:
            if a.get("type") not in KNOWN_TYPES:
                schema_errs.append(f"unknown artifact type: {a.get('type')}")
    if bad_refs:
        schema_errs.append(
            "workflow needs reference nonexistent job(s): "
            + ", ".join(f"{j}->{n}" for j, n in bad_refs[:4]))
    checks["schema"] = "pass" if not schema_errs else "fail"

    # ---- self-seal ----
    body = {k: v for k, v in cert.items() if k != "sha256"}
    checks["seal_match"] = hmac.compare_digest(
        str(cert.get("sha256", "")), sha(json.dumps(body, sort_keys=True)))

    # ---- source digest ----
    checks["source_match"] = (
        sha(open(wf_path, "rb").read()) == cert.get("source_sha"))

    # ---- artifacts ----
    fails = 0
    for a in (arts or []):
        if a.get("type") == "verdict" and "witness_chain" in a:
            ch = a["witness_chain"]
            ok = len(ch) >= 2 and all(
                (ch[i], ch[i + 1]) in edges for i in range(len(ch) - 1))
            end = ((a["a"], a["b"]) if a["verdict"] == "PROVEN_YES"
                   else (a["b"], a["a"]))
            ok = ok and (ch[0], ch[-1]) == end
            fails += not ok
        elif a.get("type") == "exhibit":
            o = a["order"]
            ok = set(o) == jobset and len(o) == len(jobset)
            if ok:
                pos = {x: i for i, x in enumerate(o)}
                ok = all(pos[u] < pos[v] for u, v in edges)
                pa, pb = a["a"], a["b"]
                ok = ok and ((pos[pa] < pos[pb])
                             == (a["direction"] == "yes"))
            fails += not ok
    checks["artifact_fails"] = fails

    checks["GREEN"] = (checks["schema"] == "pass"
                       and checks["seal_match"]
                       and checks["source_match"]
                       and fails == 0)
    print(json.dumps(checks, indent=1))
    return 0 if checks["GREEN"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
