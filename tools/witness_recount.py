#!/usr/bin/env python3
"""Exact recount verifier for Witness claims.

Independently recomputes, from the workflow file alone, using an
ideal-lattice dynamic programme over the declared job-ID DAG:
  N        the exact number of valid topological orderings;
  p(a<b)   the exact share of orderings placing a before b, as an
           integer numerator/denominator;
  N_after  the exact count after adding a proposed dependency.
With --cert, checks every numeric claim in a Witness certificate
(N, each unresolved p, each whatif N_after) against the recount.
Model: valid static job-ID topological orderings of the declared
needs graph. This is a structural share, not a runtime scheduler
frequency. Limits: up to 24 jobs (bitmask DP).
Usage:
  python3 witness_recount.py workflow.yml [a b] [--add u v]
  python3 witness_recount.py workflow.yml --cert cert.json
Requires: pyyaml. Patents pending GB2618664.3, GB2619009.0."""
import json
import sys
from fractions import Fraction

import yaml


def parse(wf):
    doc = yaml.safe_load(open(wf))
    jobs = list((doc.get("jobs") or {}).keys())
    ix = {j: i for i, j in enumerate(jobs)}
    pred = [0] * len(jobs)
    for j, s in (doc.get("jobs") or {}).items():
        needs = s.get("needs", []) if isinstance(s, dict) else []
        needs = [needs] if isinstance(needs, str) else needs
        for n in needs:
            if n in ix:
                pred[ix[j]] |= 1 << ix[n]
            else:
                raise SystemExit(
                    f"error: needs reference to nonexistent job: "
                    f"{j} -> {n}")
    return jobs, ix, pred


def count(pred, k, extra=()):
    p = list(pred)
    for u, v in extra:
        p[v] |= 1 << u
    full = (1 << k) - 1
    dp = {0: 1}
    for _ in range(k):
        nd = {}
        for mask, ways in dp.items():
            for j in range(k):
                bit = 1 << j
                if mask & bit or (p[j] & mask) != p[j]:
                    continue
                nd[mask | bit] = nd.get(mask | bit, 0) + ways
        dp = nd
    return dp.get(full, 0)


def main():
    args = sys.argv[1:]
    wf = args[0]
    jobs, ix, pred = parse(wf)
    k = len(jobs)
    if k > 24:
        raise SystemExit(f"error: {k} jobs exceeds the 24-job "
                         f"bitmask limit of this recount tool")
    N = count(pred, k)
    print(f"jobs {k} · N = {N:,} valid orderings "
          f"(static job-ID DAG model)")
    if "--cert" in args:
        cert = json.load(open(args[args.index("--cert") + 1]))
        ok = True
        if str(N) != str(cert.get("N")):
            print(f"  N MISMATCH: cert says {cert.get('N')}")
            ok = False
        for a in cert.get("artifacts", []):
            if a.get("type") == "verdict" and \
                    a.get("verdict") == "UNRESOLVED":
                num = count(pred, k, [(ix[a["a"]], ix[a["b"]])])
                frac = Fraction(num, N)
                claim = a.get("p_num"), a.get("p_den")
                if claim[0] is not None:
                    good = Fraction(claim[0], claim[1]) == frac
                else:
                    good = abs(float(a.get("p", -1))
                               - float(frac)) < 1e-9
                print(f"  p({a['a']} before {a['b']}) = "
                      f"{num}/{N} = {float(frac):.6f} "
                      f"{'ok' if good else 'MISMATCH vs cert'}")
                ok &= good
            if a.get("type") == "whatif":
                na = count(pred, k, [(ix[a["u"]], ix[a["v"]])])
                good = str(na) == str(a.get("N_after"))
                print(f"  whatif +({a['u']} -> {a['v']}): "
                      f"N_after = {na:,} "
                      f"{'ok' if good else 'MISMATCH vs cert'}")
                ok &= good
        print("RECOUNT:", "ALL CLAIMS REPRODUCED" if ok
              else "MISMATCH FOUND")
        raise SystemExit(0 if ok else 1)
    if "--add" in args:
        i = args.index("--add")
        u, v = args[i + 1], args[i + 2]
        na = count(pred, k, [(ix[u], ix[v])])
        print(f"with {u} -> {v}: N_after = {na:,} "
              f"(removes {N - na:,} orderings)")
    if len(args) >= 3 and not args[1].startswith("--"):
        a, b = args[1], args[2]
        num = count(pred, k, [(ix[a], ix[b])])
        print(f"p({a} before {b}) = {num}/{N} "
              f"= {num/N:.6f} exactly {num}/{N}")


if __name__ == "__main__":
    main()
