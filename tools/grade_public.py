#!/usr/bin/env python3
"""Score model responses against an Arcifact evidence bank.

Usage:
    python grade_public.py BANK.jsonl RESPONSES.jsonl [--pretty]

RESPONSES.jsonl carries one object per item:
    {"u": "<item uid>", "response": "POSSIBLE: <label or NONE>\nCERTAIN: <label or NONE>"}

Output is a JSON object with fields:
    n                  items scored (uids matched to the bank)
    score              mean of 0.5*[POSSIBLE correct] + 0.5*[CERTAIN correct]
    cells              per-cell means over both/possible_only/neither items
    fabrication_rate   share of named answers that name an observation
                       the gold never names (menu or resolver labels)

Copyright (c) 2026 Arcifact Ltd. Arcifact Evaluation License v1.0.
"""
import argparse
import collections
import json
import pathlib
import re
import sys


def parse(resp):
    p = c = None
    for line in resp.splitlines():
        m = re.match(r"\s*POSSIBLE:\s*(.+)", line, re.I)
        if m:
            p = m.group(1).strip()
        m = re.match(r"\s*CERTAIN:\s*(.+)", line, re.I)
        if m:
            c = m.group(1).strip()
    return p, c


def canon(x):
    return re.sub(r"\s+", " ", (x or "").strip().casefold()).rstrip(".")


def grade(bank_path, resp_path):
    bank = {}
    for line in pathlib.Path(bank_path).read_text().splitlines():
        row = json.loads(line)
        bank[row["u"]] = row
    n = 0
    correct = 0.0
    cells = collections.defaultdict(list)
    named = fab = 0
    for line in pathlib.Path(resp_path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        it = bank.get(r.get("u"))
        if not it:
            continue
        g = it["g"]
        n += 1
        p, c = parse(r.get("response", ""))
        gp = {canon(x) for x in g["resolver_possible"]}
        gc = {canon(x) for x in g["resolver_certain"]}
        # An observation is fabricated only if the gold itself never
        # names it: menu entries and resolver labels are all real.
        known = {canon(x) for x in g["menu"]} | gp | gc
        rw = 0.5 * (canon(p) in gp) + 0.5 * (canon(c) in gc)
        for x in (p, c):
            if x and canon(x) != "none":
                named += 1
                if canon(x) not in known:
                    fab += 1
        correct += rw
        cell = ("both" if g["resolver_certain"] != ["NONE"] else
                "possible_only" if g["resolver_possible"] != ["NONE"]
                else "neither")
        cells[cell].append(rw)
    return {"n": n, "score": round(correct / max(n, 1), 4),
            "cells": {k: round(sum(v) / len(v), 3)
                      for k, v in sorted(cells.items())},
            "fabrication_rate": round(fab / max(named, 1), 3)}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Score responses against an Arcifact evidence bank.")
    ap.add_argument("bank", type=pathlib.Path)
    ap.add_argument("responses", type=pathlib.Path)
    ap.add_argument("--pretty", action="store_true",
                    help="indent the JSON output")
    args = ap.parse_args(argv)
    for path in (args.bank, args.responses):
        if not path.is_file():
            print(f"error: no such file: {path}", file=sys.stderr)
            return 2
    out = grade(args.bank, args.responses)
    if out["n"] == 0:
        print("error: no response uids matched the bank",
              file=sys.stderr)
        return 2
    print(json.dumps(out, indent=1 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
