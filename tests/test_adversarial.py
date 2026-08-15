"""Adversarial tests for the Arcifact verification boundary. The
measurement system is attacked here as hard as the systems it
measures. Fixtures are committed IN this directory so every test runs
in public CI; none is a no-op. Signature tests require pynacl and skip
explicitly (not silently) when it is absent."""
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
BANKS = ROOT / "banks"
FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
PY = sys.executable
SCHEMA = ROOT / "manifests" / "certificate.schema.v1.json"

try:
    import nacl.signing  # noqa
    HAVE_NACL = True
except ImportError:
    HAVE_NACL = False


def run(args):
    return subprocess.run([PY, *map(str, args)], capture_output=True,
                          text=True)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


# ================= scorer =================
def a_bank():
    return [json.loads(l) for l in
            (BANKS / "eval_autocsv.jsonl").read_text().splitlines()
            if l.strip()]


def neither(uid):
    return {"u": uid, "response": "POSSIBLE: NONE\nCERTAIN: NONE"}


def grade(resp, *extra):
    p = FIX.parent / "_tmp_resp.jsonl"
    p.write_text("".join(json.dumps(x) + "\n" for x in resp))
    r = run([TOOLS / "grade_public.py", BANKS / "eval_autocsv.jsonl",
             p, *extra])
    p.unlink(missing_ok=True)
    try:
        return json.loads(r.stdout), r.returncode
    except json.JSONDecodeError:
        return {}, r.returncode


def test_duplicate_uid_not_counted():
    out, _ = grade([neither(a_bank()[0]["u"])] * 5)
    assert out["n"] == 1 and out["duplicate_n"] == 4


def test_duplicate_fatal_in_strict():
    _, rc = grade([neither(a_bank()[0]["u"])] * 5, "--strict")
    assert rc == 3


def test_unknown_and_missing_reported():
    out, _ = grade([neither(a_bank()[0]["u"]),
                    {"u": "deadbeefdead", "response": "POSSIBLE: NONE"}])
    assert out["unknown_n"] == 1 and out["missing_n"] == out["bank_n"] - 1


def test_strict_requires_full_coverage():
    _, rc = grade([neither(a_bank()[0]["u"])], "--strict")
    assert rc == 3


def test_gold_scores_full_strict():
    rows = []
    for it in a_bank():
        g = it["g"]
        pl = g["resolver_possible"][0]
        cl = g["resolver_certain"][0]
        rows.append({"u": it["u"],
                     "response": f"POSSIBLE: {pl}\nCERTAIN: {cl}"})
    out, rc = grade(rows, "--strict")
    assert rc == 0 and out["score"] == 1.0 and out["coverage"] == 1.0


# ================= bank integrity =================
def test_bank_uids_unique():
    for f in BANKS.glob("*.jsonl"):
        u = [json.loads(l)["u"] for l in f.read_text().splitlines()
             if l.strip()]
        assert len(u) == len(set(u)), f


def test_bank_digests_match_manifest_full():
    man = json.loads((BANKS / "BANKS_MANIFEST.json").read_text())
    for name, meta in man.items():
        full = sha((BANKS / name).read_bytes())
        assert meta["sha256"] == full, name
        assert len(meta["sha256"]) == 64, name


# ================= witness verifier =================
def wit(cert, wf=FIX / "workflow_syn.yml"):
    r = run([TOOLS / "witness_verify_light.py", cert, wf])
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"GREEN": False}


def reseal_witness(c):
    body = {k: v for k, v in c.items() if k != "sha256"}
    c["sha256"] = sha(canon(body).encode()) if False else \
        hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return c


def test_clean_witness_green():
    assert wit(FIX / "cert_syn.json")["GREEN"] is True


def test_tampered_seal_red(tmp_path):
    c = json.loads((FIX / "cert_syn.json").read_text())
    c["sha256"] = "0" * 64
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    r = wit(p)
    assert r["GREEN"] is False and r["seal_match"] is False


def test_empty_artifacts_red(tmp_path):
    c = json.loads((FIX / "cert_syn.json").read_text())
    c["artifacts"] = []
    p = tmp_path / "c.json"
    p.write_text(json.dumps(reseal_witness(c)))
    r = wit(p)
    assert r["GREEN"] is False and r["schema"] == "fail"


def test_unknown_artifact_type_red(tmp_path):
    c = json.loads((FIX / "cert_syn.json").read_text())
    c["artifacts"].append({"type": "backdoor"})
    p = tmp_path / "c.json"
    p.write_text(json.dumps(reseal_witness(c)))
    assert wit(p)["GREEN"] is False


def test_phantom_job_exhibit_red(tmp_path):
    c = json.loads((FIX / "cert_syn.json").read_text())
    for a in c["artifacts"]:
        if a.get("type") == "exhibit":
            for i, x in enumerate(a["order"]):
                if x not in (a["a"], a["b"]):
                    a["order"][i] = "PHANTOM"
                    break
            break
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert wit(p)["GREEN"] is False


def test_dropped_job_exhibit_red(tmp_path):
    c = json.loads((FIX / "cert_syn.json").read_text())
    for a in c["artifacts"]:
        if a.get("type") == "exhibit":
            a["order"] = a["order"][:-1]
            break
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert wit(p)["GREEN"] is False


# ================= certificate verifier =================
SAMPLE = ROOT / "examples" / "sample_certificate.json"
KEYS = FIX / "issuer_keys.json"
MSET = ROOT / "examples" / "manifest_set.json"


def cv(cert, *extra):
    r = run([TOOLS / "verify_certificate.py", cert,
             "--schema", SCHEMA, *extra])
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"verdict": "ERROR"}


def test_issued_sample_valid():
    d = cv(SAMPLE, "--issuer-keys", KEYS, "--banks", BANKS,
           "--manifest-set", MSET, "--profile", "issued")
    assert d["verdict"] == "VALID"


def test_malformed_cert_invalid(tmp_path):
    c = json.loads(SAMPLE.read_text())
    c["backdoor"] = True
    c["banks"][0]["n"] = "not-int"
    c["stance"] = "not-object"
    body = {k: v for k, v in c.items() if k != "sha256"}
    c["sha256"] = hashlib.sha256(canon(body).encode()).hexdigest()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert cv(p)["verdict"] == "INVALID"


def test_field_tamper_breaks_seal(tmp_path):
    c = json.loads(SAMPLE.read_text())
    c["fabrication_rate"] = 0.99
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert cv(p)["matrix"]["seal"] == "fail"


def test_signature_strip_not_valid_as_issued(tmp_path):
    c = json.loads(SAMPLE.read_text())
    c.pop("signature", None)
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    d = cv(p, "--issuer-keys", KEYS, "--banks", BANKS, "--profile",
           "issued")
    assert d["verdict"] != "VALID"


@pytest.mark.skipif(not HAVE_NACL, reason="pynacl required")
def test_attacker_key_rejected(tmp_path):
    import nacl.signing
    import nacl.encoding
    sk = nacl.signing.SigningKey.generate()
    c = json.loads(SAMPLE.read_text())
    body = {k: v for k, v in c.items()
            if k not in ("sha256", "signature")}
    c["sha256"] = hashlib.sha256(canon(body).encode()).hexdigest()
    sbody = {k: v for k, v in c.items() if k != "signature"}
    c["signature"] = {"alg": "ed25519", "key_id": "attacker",
        "public_key": sk.verify_key.encode(
            nacl.encoding.HexEncoder).decode(),
        "sig": sk.sign(canon(sbody).encode()).signature.hex()}
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    d = cv(p, "--issuer-keys", KEYS, "--profile", "issued")
    assert d["verdict"] == "INVALID"
    assert d["matrix"]["issuer_signature"] == "untrusted_key"


def test_no_anchor_issued_incomplete():
    d = cv(SAMPLE, "--banks", BANKS, "--profile", "issued")
    assert d["verdict"] == "INCOMPLETE"


def test_expired_cert_invalid(tmp_path):
    c = json.loads(SAMPLE.read_text())
    c["expires"] = "2020-01-01T00:00:00Z"
    body = {k: v for k, v in c.items()
            if k not in ("sha256", "signature")}
    c["sha256"] = hashlib.sha256(canon(body).encode()).hexdigest()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert cv(p)["verdict"] == "INVALID"


def test_expiry_before_issued_invalid(tmp_path):
    c = json.loads(SAMPLE.read_text())
    c["issued"] = "2027-01-01T00:00:00Z"
    c["expires"] = "2026-01-01T00:00:00Z"
    body = {k: v for k, v in c.items()
            if k not in ("sha256", "signature")}
    c["sha256"] = hashlib.sha256(canon(body).encode()).hexdigest()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(c))
    assert cv(p)["verdict"] == "INVALID"


def test_revoked_cert_invalid(tmp_path):
    c = json.loads(SAMPLE.read_text())
    rev = tmp_path / "rev.json"
    rev.write_text(json.dumps({"revoked": [c["sha256"]]}))
    d = cv(SAMPLE, "--issuer-keys", KEYS, "--banks", BANKS,
           "--manifest-set", MSET, "--revocation", rev,
           "--profile", "issued")
    assert d["verdict"] == "INVALID"


def test_manifest_set_tamper_invalid(tmp_path):
    # a manifest-set with a wrong member digest must fail
    idx = json.loads(MSET.read_text())
    idx["members"][0]["sha256"] = "f" * 64
    p = tmp_path / "mset.json"
    p.write_text(json.dumps(idx))
    d = cv(SAMPLE, "--issuer-keys", KEYS, "--banks", BANKS,
           "--manifest-set", p, "--profile", "issued")
    assert d["matrix"]["manifest_set"] == "fail"
