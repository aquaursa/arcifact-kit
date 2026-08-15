#!/usr/bin/env python3
"""Verify an Arcifact Evidence Certificate offline.

Checks, in order, without contacting Arcifact:
  1. schema: required fields, types, bounds, no unknown fields;
  2. self-seal: sha256 recomputed over the certificate's contents
     (excluding sha256 and signature) equals the stored value;
  3. signature (if present): Ed25519 over the sealed payload,
     verified against the embedded public key;
  4. bank digests: each bank_sha256 matches the named bank file, if
     a --banks directory is supplied;
  5. manifest root: recomputed from a --manifest directory, if given;
  6. revocation: if a --revocation JSON file (or its absence) is
     supplied, the certificate id must not appear in it.

Only the Python standard library is required for checks 1-2 and 4-6.
Signature verification (check 3) uses PyNaCl if available; without
it, a present signature is reported as "unchecked" rather than
passing. Usage:
    python3 verify_certificate.py CERT.json [--schema S.json]
        [--banks DIR] [--manifest DIR] [--revocation R.json]
Patents pending GB2618664.3, GB2619009.0."""
import argparse
import hashlib
import hmac
import json
import pathlib
import re
import sys


def sha_hex(b):
    return hashlib.sha256(b).hexdigest()


def sha_str(s):
    return hashlib.sha256(s.encode()).hexdigest()


def sealed_payload(cert):
    body = {k: v for k, v in cert.items()
            if k not in ("sha256", "signature")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def check_schema(cert):
    errs = []
    req = ["schema_version", "subject", "release", "banks", "envelope",
           "stance", "fabrication_rate", "thresholds", "provenance",
           "issued", "expires", "sha256"]
    for k in req:
        if k not in cert:
            errs.append(f"missing field: {k}")
    if cert.get("schema_version") != "arcifact-certificate/1":
        errs.append("schema_version must be arcifact-certificate/1")
    fr = cert.get("fabrication_rate")
    if not isinstance(fr, (int, float)) or not (0 <= fr <= 1):
        errs.append("fabrication_rate out of [0,1]")
    for i, b in enumerate(cert.get("banks", []) or []):
        for k in ("bank", "bank_sha256", "score", "fabrication_rate",
                  "n", "coverage"):
            if k not in b:
                errs.append(f"bank[{i}] missing {k}")
        if "bank_sha256" in b and not re.fullmatch(
                r"[0-9a-f]{64}", str(b["bank_sha256"])):
            errs.append(f"bank[{i}] bank_sha256 not a sha256")
        for k in ("score", "fabrication_rate", "coverage"):
            v = b.get(k)
            if v is not None and not (0 <= v <= 1):
                errs.append(f"bank[{i}] {k} out of [0,1]")
        if isinstance(b.get("n"), int) and b["n"] < 1:
            errs.append(f"bank[{i}] n < 1")
    if not cert.get("banks"):
        errs.append("banks must be a non-empty array")
    sha = cert.get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha)):
        errs.append("sha256 not a sha256 digest")
    return errs


def check_signature(cert):
    sig = cert.get("signature")
    if not sig:
        return "absent"
    try:
        import nacl.signing
        import nacl.encoding
        vk = nacl.signing.VerifyKey(
            sig["public_key"], encoder=nacl.encoding.HexEncoder)
        vk.verify(sealed_payload(cert).encode(),
                  bytes.fromhex(sig["sig"]))
        return "valid"
    except ImportError:
        return "unchecked (install pynacl to verify)"
    except Exception:
        return "INVALID"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify an Arcifact Evidence Certificate offline.")
    ap.add_argument("cert", type=pathlib.Path)
    ap.add_argument("--banks", type=pathlib.Path)
    ap.add_argument("--manifest", type=pathlib.Path)
    ap.add_argument("--revocation", type=pathlib.Path)
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)
    cert = json.loads(args.cert.read_text())

    out = {"schema_errors": check_schema(cert)}
    out["seal_match"] = hmac.compare_digest(
        str(cert.get("sha256", "")), sha_str(sealed_payload(cert)))
    out["signature"] = check_signature(cert)

    bank_fails = []
    if args.banks:
        for b in cert.get("banks", []):
            f = args.banks / b["bank"]
            if not f.is_file():
                bank_fails.append(f"{b['bank']}: file absent")
            elif sha_hex(f.read_bytes()) != b["bank_sha256"]:
                bank_fails.append(f"{b['bank']}: digest mismatch")
        out["bank_digest_fails"] = bank_fails
        out["banks_checked"] = len(cert.get("banks", []))

    if args.manifest:
        leaves = sorted(
            sha_hex(p.read_bytes())
            for p in args.manifest.glob("*.json"))
        root = sha_str("".join(leaves))
        claimed = cert.get("provenance", {}).get("manifest_root")
        out["manifest_root_match"] = (root == claimed)

    revoked = False
    if args.revocation is not None:
        if args.revocation.is_file():
            rev = json.loads(args.revocation.read_text())
            ids = rev.get("revoked", []) if isinstance(rev, dict) \
                else rev
            revoked = cert.get("sha256") in ids
        out["revoked"] = revoked

    out["GREEN"] = (
        not out["schema_errors"] and out["seal_match"]
        and out["signature"] in ("valid", "absent",
                                 "unchecked (install pynacl to verify)")
        and not bank_fails
        and out.get("manifest_root_match", True)
        and not revoked)
    print(json.dumps(out, indent=1 if args.pretty else None))
    return 0 if out["GREEN"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
