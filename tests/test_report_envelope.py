"""Regression tests for the common Arcifact report envelope.

The envelope is the ecosystem's load-bearing abstraction: if it can be
made to pass a record that overstates itself, every instrument built on
it inherits that. These tests pin the refusals, not the acceptances.
"""
import json
import os
import subprocess
import sys
import copy
import hashlib

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "verify_report.py")
REC = os.path.join(HERE, "..", "examples", "reports",
                   "gate-trunk.report.json")
MODEL = os.path.join(HERE, "..", "examples", "reports",
                     "model-example.report.json")
PY = sys.executable


def _run(rec_obj, extra=None, tmp=None):
    path = tmp or "/tmp/_envelope_test.json"
    json.dump(rec_obj, open(path, "w"))
    out = subprocess.run([PY, TOOL, path] + (extra or []),
                         capture_output=True, text=True)
    verdict = [l.split()[-1] for l in out.stdout.splitlines()
               if l.startswith("VERDICT")]
    return (verdict[0] if verdict else "?"), out.stdout


def _reseal(r):
    body = {k: v for k, v in r.items() if k != "sha256"}
    r["sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    return r


def base():
    return json.load(open(REC))


def test_shipped_records_are_self_consistent():
    for p in (REC, MODEL):
        v, _ = _run(json.load(open(p)))
        assert v in ("SELF_CONSISTENT_REPORT", "INCOMPLETE"), (p, v)


def test_tampered_payload_breaks_the_seal():
    r = base()
    r["payload"]["ordering_counts"]["gate_first"] = "1"
    v, out = _run(r)
    assert v == "INVALID" and "seal does not recompute" in out


def test_resealed_but_incoherent_counts_still_fail():
    # re-sealing defeats the seal check, so semantics must catch it
    r = base()
    r["payload"]["ordering_counts"]["gate_first"] = "99999"
    v, out = _run(_reseal(r))
    assert v == "INVALID" and "ordering counts incoherent" in out


def test_job_cannot_be_both_covered_and_uncovered():
    r = base()
    r["payload"]["covered_jobs"].append("action_tests")
    v, out = _run(_reseal(r))
    assert v == "INVALID" and "both covered and uncovered" in out


def test_envelope_must_declare_something_out_of_scope():
    r = base()
    r["envelope"]["out_of_scope"] = []
    v, _ = _run(_reseal(r))
    assert v == "INVALID"


def test_unresolved_claim_must_name_what_settles_it():
    r = base()
    for c in r["claims"]:
        c.pop("settled_by", None)
        if c["verdict"] == "unresolved":
            pass
    v, out = _run(_reseal(r))
    assert v == "INVALID" and "would settle" in out


def test_unverified_assumption_must_say_how_to_check():
    r = base()
    r["assumptions"][0].pop("how_to_verify")
    v, out = _run(_reseal(r))
    assert v == "INVALID" and "no way to check" in out


def test_issued_profile_requires_a_signature():
    r = base()
    r["profile"] = "issued"
    v, out = _run(_reseal(r))
    assert v == "INVALID" and "requires a signature" in out


def test_requested_profile_is_a_floor_not_a_downgrade():
    v, out = _run(base(), ["--profile", "issued"])
    assert v == "INVALID" and "weaker than the required" in out


def test_source_mismatch_is_a_failure_not_an_omission():
    os.makedirs("/tmp/_bad_src", exist_ok=True)
    src = os.path.join(HERE, "..", "..", "site_pub",
                       "manifests", "report.schema.v1.json")
    open("/tmp/_bad_src/pr.yaml", "w").write("not the workflow\n")
    v, out = _run(base(), ["--sources", "/tmp/_bad_src"])
    assert v == "INVALID" and "source mismatch" in out


def test_unknown_instrument_is_incomplete_not_valid():
    r = base()
    r["instrument"] = "some-future-instrument"
    v, out = _run(_reseal(r))
    # schema pins the enum, so this must not silently pass
    assert v in ("INVALID", "INCOMPLETE")
    assert "VALID" != v
