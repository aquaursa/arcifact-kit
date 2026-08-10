#!/usr/bin/env python3
"""Run any OpenAI-compatible model against a bank, then grade it.

The point of this tool is that you do not have to take our word for
anything. Point it at your own endpoint, run a bank, and score the
responses with the same semantics used in Arcifact certificates.

Usage:
    export OPENAI_API_KEY=...            # your key, never stored
    export OPENAI_BASE=https://api.openai.com/v1   # or any compatible base
    export OPENAI_MODEL=gpt-4o           # any chat model name
    python tools/run_frontier.py banks/evalw_numeric.jsonl out/responses.jsonl
    python tools/grade_public.py banks/evalw_numeric.jsonl out/responses.jsonl

Uses only the standard library. One request per item, temperature 0.

Copyright (c) 2026 Arcifact Ltd. Arcifact Evaluation License v1.0.
"""
import argparse
import json
import os
import pathlib
import sys
import time
import urllib.request


def ask(base, key, model, prompt, timeout=60):
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=json.dumps({
            "model": model,
            "temperature": 0,
            "max_tokens": 200,
            "messages": [{"role": "user", "content": prompt}],
        }).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.load(resp)
    return body["choices"][0]["message"]["content"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Collect model responses for an Arcifact bank.")
    ap.add_argument("bank", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N items (0 = full bank)")
    ap.add_argument("--sleep", type=float, default=0.0,
                    help="seconds between requests")
    args = ap.parse_args(argv)
    key = os.environ.get("OPENAI_API_KEY")
    base = os.environ.get("OPENAI_BASE", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL")
    if not key or not model:
        print("error: set OPENAI_API_KEY and OPENAI_MODEL", file=sys.stderr)
        return 2
    if not args.bank.is_file():
        print(f"error: no such file: {args.bank}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in args.bank.read_text().splitlines()]
    if args.limit:
        rows = rows[: args.limit]
    with args.out.open("w") as fh:
        for i, row in enumerate(rows, 1):
            text = ask(base, key, model, row["p"])
            fh.write(json.dumps({"u": row["u"], "response": text}) + "\n")
            fh.flush()
            print(f"\r{i}/{len(rows)}", end="", file=sys.stderr)
            if args.sleep:
                time.sleep(args.sleep)
    print(f"\nwrote {len(rows)} responses to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
