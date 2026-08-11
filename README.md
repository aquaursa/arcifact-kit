# Arcifact Evidence Instrument Kit

![verify](https://github.com/arcifact/arcifact-kit/actions/workflows/verify.yml/badge.svg)

Frozen, attack-gated evaluation banks for measuring one specific
failure mode in language models: fabricated evidence. Each item asks
which single observation could settle a stated question. Models that
guess name observations that do not exist. This kit lets anyone
score that behavior with the exact semantics used in Arcifact
certificates, against banks whose integrity is hash-verified.

## For evaluators, before anything else

Running this kit sends nothing to us. `run_frontier.py` calls the
endpoint YOU configure and writes responses to YOUR disk; the
scorer runs locally; there is no telemetry, no account, and no
network access beyond your own model endpoint. Vendors under
confidentiality can therefore measure internal models freely.
Only you decide whether a result is ever shared.

## Sixty seconds, your model, our banks

```
export OPENAI_API_KEY=...  OPENAI_MODEL=gpt-4o        # any compatible endpoint
python tools/run_frontier.py banks/evalw_numeric.jsonl out/r.jsonl --limit 25
python tools/grade_public.py banks/evalw_numeric.jsonl out/r.jsonl --pretty
```

Watch the `fabrication_rate` field. On rendered-numeric items,
frontier chat models typically name observations that do not exist
on most items; Arcifact's governed configuration scores 1.000 with
fabrication 0.000 on the same bank (provenance in
`docs/BASELINES.md`). Nothing here asks to be believed: run it.

## Quick start

No dependencies beyond Python 3.10+.

```
python tools/verify_hashes.py
python tools/grade_public.py banks/eval_autocsv.jsonl your_responses.jsonl
```

Responses are JSONL, one object per bank item:

```
{"u": "<item uid>", "response": "POSSIBLE: <label or NONE>\nCERTAIN: <label or NONE>"}
```

`examples/abstain_baseline.jsonl` is a runnable reference input; the
scorer prints per-cell accuracy and the fabrication rate (answers
naming observations absent from the item menu).

## Banks

| bank | items | sha256 (16) |
|---|---:|---|
| `eval_autocsv.jsonl` | 40 | `63d47bf352d5b25d` |
| `eval_autocsvA.jsonl` | 40 | `c903490dfc3138fa` |
| `eval_autospec.jsonl` | 40 | `c519714f84f445dd` |
| `eval_cardinality.jsonl` | 150 | `a53aca5d26ca355d` |
| `eval_ciplan.jsonl` | 40 | `64cc550fe28969cb` |
| `eval_numeric.jsonl` | 150 | `4a3bd080927aa601` |
| `eval_schema.jsonl` | 40 | `ad1cd39599103b14` |
| `eval_temporal.jsonl` | 150 | `9dfa225d13cf6402` |
| `evalw_numeric.jsonl` | 150 | `4a3bd080927aa601` |
| `evalw_temporal.jsonl` | 150 | `8c555aeb6fd12374` |

Score every bank in one loop:

```
for b in banks/*.jsonl; do python tools/grade_public.py "$b" your_responses.jsonl; done
```

## What a score means

POSSIBLE asks for an observation with at least one decisive outcome;
CERTAIN asks for one decisive on every outcome. Labels are exact by
construction. Cells (`both`, `possible_only`, `neither`) separate
stance from computation: abstaining when nothing is entitled is
scored, and so is committing when something is. See
`docs/CERT_SCHEMA.md` for envelope reporting and failure phenotypes,
and `docs/BASELINES.md` for published reference numbers with
provenance.

## Reference results

| system | rendered numeric (150) | fabrication |
|---|---:|---:|
| governed pipeline (Arcifact) | 1.000 | 0.000 |
| ungoverned base 9B | 0.000 | ~1.000 |
| abstain-everything baseline | 0.500 | 0.000 |

Full per-bank numbers, envelopes, and provenance:
`docs/BASELINES.md`. Measurement rules, attack gating, and
preregistration policy: `docs/PROTOCOL.md`. Verified rows from
other teams are welcome by pull request: attach the responses file
and the exact command; rows are checked by re-grading before merge.

## Scope

Banks are frozen artifacts. Construction internals and generators are deliberately absent: this repository is for
verification. Commercial certification and new-domain onboarding are
available from Arcifact Ltd.

## License

Research and internal evaluation use permitted. Training on, or
distillation from, these banks or from published responses to them
is not permitted. See `LICENSE.md`.

## Status

Patent pending: United Kingdom application GB2618664.3. Banks and
scorer semantics are frozen under the license above; certification
against these instruments is provided commercially by Arcifact Ltd.

## The invitation

Distrust is the intended first response. Verify the digests, run your own model, read docs/PROTOCOL.md, and check every number against the bar registered before its run. The site is the short version: https://arcifact.io
