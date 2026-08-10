# Published Baselines (provenance: Merkle-rooted run log)
All numbers are single greedy runs on the frozen banks in this kit,
graded by tools/grade_public.py semantics. Base model: Qwen3.5-9B.
Frontier rows (cap-audited, effort-controlled): gpt-5.1, gpt-4.1,
gpt-5-mini.

| bank | base-9B | fabrication | frontier best |
|---|---|---|---|
| engine (150, internal-only bank) | ~floor | 1.000 | fab 1.000 all three |
| rendered numeric (150) | 0.02-class | high | 0.000 all three |
| autospec - live Stripe/Petstore (40) | 0.150 | 0.921 | not yet run |
| autocsv - live measurements CSV (40) | 0.225 | 0.812 | not yet run |
| ciplan - live pytorch CI dag (40) | 0.350 | 0.100* | not yet run |

*ciplan exhibits the abstention-collapse phenotype (blanket NONE)
rather than fabrication: both-cell 0.000.

Arcifact's governed pipeline reference numbers on the same banks,
from a single governed configuration: rendered
numeric 1.000; temporal 1.000; ciplan 1.000 (all cells); autospec
0.897 and autocsvA 1.000 within the certified H<=12 envelope; and
a never-seen corpus (diamonds.csv, 53,941 records) at 0.963
in-envelope ZERO-SHOT with structurally zero fabrication. Every
number traces to a pre-registered bar. Envelope reporting is part
of the certificate schema by policy.
