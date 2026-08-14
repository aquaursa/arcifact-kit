#!/usr/bin/env python3
"""Witness light verifier. Checks a Witness certificate against
the workflow file it was issued for: source digest, every witness
chain edge by edge, every exhibit schedule for validity and
direction. No reconstruction of the schedule space is performed;
counts are recomputed only in full-mode verification, available
under evaluation terms. Usage:
  python3 witness_verify_light.py cert.json workflow.yml
Requires: pyyaml. Patents pending GB2618664.3, GB2619009.0."""
import json, sys, hashlib, yaml

cert, wf = json.load(open(sys.argv[1])), sys.argv[2]
doc = yaml.safe_load(open(wf)); jobs = doc.get("jobs", {})
edges = set()
for j, s in jobs.items():
    needs = s.get("needs", []) if isinstance(s, dict) else []
    needs = [needs] if isinstance(needs, str) else needs
    for n in needs:
        if n in jobs: edges.add((n, j))
src_ok = hashlib.sha256(open(wf, "rb").read()).hexdigest() \
    == cert["source_sha"]
fails = 0
for a in cert["artifacts"]:
    if a["type"] == "verdict" and "witness_chain" in a:
        ch = a["witness_chain"]
        ok = all((ch[i], ch[i+1]) in edges
                 for i in range(len(ch)-1))
        end = (a["a"], a["b"]) if a["verdict"] == "PROVEN_YES" \
            else (a["b"], a["a"])
        fails += not (ok and (ch[0], ch[-1]) == end)
    elif a["type"] == "exhibit":
        o = a["order"]; pos = {x: i for i, x in enumerate(o)}
        ok = len(set(o)) == len(jobs) and all(
            pos[u] < pos[v] for u, v in edges)
        pa, pb = (a["a"], a["b"])
        ok &= (pos[pa] < pos[pb]) == (a["direction"] == "yes")
        fails += not ok
print(json.dumps({"source_match": src_ok,
    "artifact_fails": fails,
    "GREEN": src_ok and fails == 0}, indent=1))
