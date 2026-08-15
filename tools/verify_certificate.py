#!/usr/bin/env python3
"""Verify an Arcifact Evidence Certificate offline.

The verdict is a matrix, not a single flag. Each dimension is one of
"pass", "fail", "not_checked", or "not_applicable". The overall
verdict is:
  VALID        every mandatory dimension passed (issued profile);
  INCOMPLETE   nothing failed, but a mandatory check could not run
               (e.g. no trust anchor supplied, signature unverifiable);
  INVALID      any dimension failed.

Crucially:
  - the published closed JSON Schema is loaded and enforced when the
    jsonschema package is available; a lightweight bounded checker
    runs otherwise, and its reduced strength is reported;
  - the issuer signature is verified against a trust anchor supplied
    OUTSIDE the certificate (an issuer-keys file, or a key pinned via
    --issuer-key); a public key embedded in the certificate is never
    trusted on its own;
  - an unverifiable or absent signature on a certificate that claims
    the "issued" profile is INVALID/INCOMPLETE, never VALID (fail
    closed, no signature-stripping downgrade);
  - expiry, issued<expires, bank digests, manifest set and revocation
    are each checked and reported explicitly.

Usage:
    python3 verify_certificate.py CERT.json
        [--schema certificate.schema.v1.json]
        [--issuer-keys issuer_keys.json | --issuer-key HEX]
        [--banks DIR] [--manifest-set INDEX.json]
        [--revocation revocation.json] [--profile issued|report|draft]
        [--pretty]
Standard library only for schema (lightweight), seal, digests, set and
revocation. Signature verification uses PyNaCl; if unavailable, a
present signature is reported unverifiable and fails the issued
profile. Patents pending GB2618664.3, GB2619009.0."""
import argparse
import hashlib
import hmac
import json
import pathlib
import re
import sys

SCHEMA_ID = "arcifact-certificate/1"


def sha_hex(b):
    return hashlib.sha256(b).hexdigest()


def canon(obj):
    # RFC 8785-style compact canonical JSON (sorted keys, no spaces).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sealed_payload(cert):
    body = {k: v for k, v in cert.items()
            if k not in ("sha256", "signature")}
    return canon(body)


def signed_payload(cert):
    # signature covers everything except the signature block itself,
    # including sha256, so the seal cannot be re-computed to erase a
    # stripped signature without detection at the signature layer.
    body = {k: v for k, v in cert.items() if k != "signature"}
    return canon(body)


# ---------- schema enforcement ----------
def check_schema(cert, schema_path):
    # Prefer full JSON-Schema enforcement of the published closed
    # schema; fall back to a bounded hand check that still rejects the
    # attacks in the review (wrong types, unknown fields, bad dates).
    if schema_path and schema_path.is_file():
        try:
            import jsonschema
            schema = json.loads(schema_path.read_text())
            errs = sorted(jsonschema.Draft202012Validator(schema)
                          .iter_errors(cert),
                          key=lambda e: e.path)
            return ("pass" if not errs else "fail",
                    [f"{'/'.join(map(str, e.path))}: {e.message}"
                     for e in errs[:12]], "jsonschema")
        except ImportError:
            pass
    # bounded fallback
    errs = []
    if cert.get("schema_version") != SCHEMA_ID:
        errs.append("schema_version must be " + SCHEMA_ID)
    allowed = {"schema_version", "subject", "release", "banks",
               "envelope", "stance", "fabrication_rate", "thresholds",
               "provenance", "issued", "expires", "revocation",
               "signature", "sha256", "profile"}
    for k in cert:
        if k not in allowed:
            errs.append(f"unknown top-level field: {k}")
    for k in ("subject", "release", "envelope"):
        if not isinstance(cert.get(k), str) or not cert.get(k):
            errs.append(f"{k} must be a non-empty string")
    st = cert.get("stance")
    if not isinstance(st, dict):
        errs.append("stance must be an object")
    else:
        for k in ("answers", "entitled_refusals", "errors"):
            if not isinstance(st.get(k), int) or st.get(k) < 0:
                errs.append(f"stance.{k} must be a non-negative int")
    fr = cert.get("fabrication_rate")
    if not isinstance(fr, (int, float)) or not (0 <= fr <= 1):
        errs.append("fabrication_rate out of [0,1]")
    banks = cert.get("banks")
    if not isinstance(banks, list) or not banks:
        errs.append("banks must be a non-empty array")
    else:
        seen = set()
        allowed_b = {"bank", "bank_sha256", "score", "fabrication_rate",
                     "n", "coverage", "raw"}
        for i, b in enumerate(banks):
            if not isinstance(b, dict):
                errs.append(f"bank[{i}] must be an object")
                continue
            for k in b:
                if k not in allowed_b:
                    errs.append(f"bank[{i}] unknown field: {k}")
            name = b.get("bank")
            if name in seen:
                errs.append(f"duplicate bank entry: {name}")
            seen.add(name)
            if not re.fullmatch(r"[0-9a-f]{64}",
                                str(b.get("bank_sha256", ""))):
                errs.append(f"bank[{i}] bank_sha256 not full sha256")
            if not isinstance(b.get("n"), int) or b.get("n", 0) < 1:
                errs.append(f"bank[{i}] n must be a positive int")
            for k in ("score", "fabrication_rate", "coverage"):
                v = b.get(k)
                if not isinstance(v, (int, float)) or not (0 <= v <= 1):
                    errs.append(f"bank[{i}] {k} out of [0,1]")
    ths = cert.get("thresholds")
    if not isinstance(ths, list) or not ths:
        errs.append("thresholds must be a non-empty array")
    else:
        for i, t in enumerate(ths):
            if not isinstance(t, dict) or "registered_at" not in t:
                errs.append(f"threshold[{i}] malformed")
    for k in ("issued", "expires"):
        v = cert.get(k, "")
        if not re.match(r"\d{4}-\d{2}-\d{2}T", str(v)):
            errs.append(f"{k} not an ISO-8601 datetime")
    if not re.fullmatch(r"[0-9a-f]{64}", str(cert.get("sha256", ""))):
        errs.append("sha256 not a full sha256 digest")
    return ("pass" if not errs else "fail", errs, "builtin")


# ---------- signature against an external anchor ----------
def load_anchor(args):
    if args.issuer_key:
        return {"cli": args.issuer_key.lower()}
    if args.issuer_keys and args.issuer_keys.is_file():
        doc = json.loads(args.issuer_keys.read_text())
        return {k["key_id"]: k["public_key"].lower()
                for k in doc.get("keys", [])
                if k.get("status", "active") == "active"}
    return None


def check_signature(cert, anchor):
    sig = cert.get("signature")
    if not sig:
        return "absent", None
    if anchor is None:
        return "no_trust_anchor", sig.get("key_id")
    kid = sig.get("key_id")
    trusted = (list(anchor.values()) if "cli" in anchor
               else [anchor[kid]] if kid in anchor else [])
    embedded = str(sig.get("public_key", "")).lower()
    # the signing key must be one the anchor recognises; an embedded
    # key that is not in the anchor is never trusted
    if not trusted or (embedded and embedded not in trusted):
        return "untrusted_key", kid
    try:
        import nacl.signing
        import nacl.encoding
        vk = nacl.signing.VerifyKey(
            trusted[0], encoder=nacl.encoding.HexEncoder)
        vk.verify(signed_payload(cert).encode(),
                  bytes.fromhex(sig["sig"]))
        return "pass", kid
    except ImportError:
        return "unverifiable_no_pynacl", kid
    except Exception:
        return "fail", kid


def check_expiry(cert):
    import datetime
    try:
        iss = cert["issued"]
        exp = cert["expires"]
        di = datetime.datetime.fromisoformat(iss.replace("Z", "+00:00"))
        de = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        if de <= di:
            return "fail"  # expires before issued
        return "current" if now < de else "expired"
    except Exception:
        return "fail"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify an Arcifact Evidence Certificate offline.")
    ap.add_argument("cert", type=pathlib.Path)
    ap.add_argument("--schema", type=pathlib.Path)
    ap.add_argument("--issuer-keys", type=pathlib.Path)
    ap.add_argument("--issuer-key", type=str,
                    help="a single trusted issuer public key (hex)")
    ap.add_argument("--banks", type=pathlib.Path)
    ap.add_argument("--manifest-set", type=pathlib.Path,
                    help="explicit manifest index JSON (never a dir)")
    ap.add_argument("--revocation", type=pathlib.Path)
    ap.add_argument("--profile", choices=["issued", "report", "draft"],
                    default=None,
                    help="required profile; defaults to the cert's own "
                         "'profile' field or 'report'")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)
    cert = json.loads(args.cert.read_text())
    profile = args.profile or cert.get("profile", "report")

    m = {}
    schema_state, schema_errs, schema_engine = check_schema(
        cert, args.schema)
    m["schema"] = schema_state
    m["schema_engine"] = schema_engine
    m["seal"] = ("pass" if hmac.compare_digest(
        str(cert.get("sha256", "")), sha_hex(sealed_payload(cert).encode()))
        else "fail")

    anchor = load_anchor(args)
    sig_state, key_id = check_signature(cert, anchor)
    m["issuer_signature"] = sig_state
    m["key_id"] = key_id

    if args.banks:
        fails = []
        for b in cert.get("banks", []):
            f = args.banks / str(b.get("bank"))
            if not f.is_file():
                fails.append(f"{b.get('bank')}: absent")
            elif sha_hex(f.read_bytes()) != b.get("bank_sha256"):
                fails.append(f"{b.get('bank')}: digest mismatch")
        m["banks"] = "pass" if not fails else "fail"
        m["bank_fails"] = fails
    else:
        m["banks"] = "not_checked"

    if args.manifest_set and args.manifest_set.is_file():
        idx = json.loads(args.manifest_set.read_text())
        if idx.get("schema") != "arcifact-manifest-set/1":
            m["manifest_set"] = "fail"
        else:
            members = idx.get("members", [])
            root = sha_hex(canon(
                [{"path": x["path"], "sha256": x["sha256"]}
                 for x in members]).encode())
            claimed = cert.get("provenance", {}).get("manifest_root")
            m["manifest_set"] = "pass" if root == claimed else "fail"
    else:
        m["manifest_set"] = "not_checked"

    if args.revocation is not None:
        if args.revocation.is_file():
            rev = json.loads(args.revocation.read_text())
            ids = rev.get("revoked", []) if isinstance(rev, dict) else rev
            m["revocation"] = ("fail" if cert.get("sha256") in ids
                               else "checked_not_revoked")
        else:
            m["revocation"] = "not_checked"
    else:
        m["revocation"] = "not_checked"

    m["expiry"] = check_expiry(cert)

    # ---- overall verdict ----
    hard_fail = (m["schema"] == "fail" or m["seal"] == "fail"
                 or m.get("banks") == "fail"
                 or m.get("manifest_set") == "fail"
                 or m.get("revocation") == "fail"
                 or m["expiry"] in ("fail", "expired")
                 or m["issuer_signature"] in ("fail", "untrusted_key"))
    # issued profile requires a verified issuer signature and evidence
    issued_reqs_met = (
        m["issuer_signature"] == "pass"
        and m.get("banks") == "pass"
        and m["schema"] == "pass" and m["seal"] == "pass"
        and m["expiry"] == "current")
    if hard_fail:
        verdict = "INVALID"
    elif profile == "issued":
        verdict = "VALID" if issued_reqs_met else "INCOMPLETE"
    else:
        # report/draft: seal + schema must pass; signature/evidence
        # may be absent, but any present-but-unverifiable signature is
        # not allowed to read as fine
        base_ok = (m["schema"] == "pass" and m["seal"] == "pass"
                   and m["expiry"] in ("current",)
                   and m["issuer_signature"] in
                   ("pass", "absent", "not_checked"))
        verdict = "VALID" if base_ok else "INCOMPLETE"

    out = {"profile": profile, "matrix": m,
           "schema_errors": schema_errs if schema_state == "fail" else [],
           "verdict": verdict}
    print(json.dumps(out, indent=1 if args.pretty else None))
    return 0 if verdict == "VALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
