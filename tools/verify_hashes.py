#!/usr/bin/env python3
"""Verify that every bank matches its published digest.

Exit status is nonzero on any mismatch, so this doubles as a CI gate
and as an integrity check for downstream consumers.
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "banks" / "BANKS_MANIFEST.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    failures = []
    for name, meta in sorted(manifest.items()):
        digest = hashlib.sha256((ROOT / "banks" / name).read_bytes())
        got = digest.hexdigest()[:16]
        ok = got == meta["sha256"]
        print(f"{'ok ' if ok else 'FAIL'} {name}  {got}")
        if not ok:
            failures.append(name)
    present = {p.name for p in (ROOT / "banks").glob("*.jsonl")}
    unknown = sorted(present - set(manifest))
    for name in unknown:
        print(f"FAIL {name}  not in manifest")
    if failures or unknown:
        print(f"{len(failures)} digest failure(s), "
              f"{len(unknown)} unmanifested file(s)", file=sys.stderr)
        return 1
    print(f"{len(manifest)} banks verified; no strays")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
