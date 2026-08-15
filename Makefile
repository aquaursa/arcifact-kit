.PHONY: verify example frontier
verify:
	python3 tools/verify_hashes.py
example:
	python3 tools/grade_public.py banks/eval_autocsv.jsonl examples/abstain_baseline_eval_autocsv.jsonl
frontier:
	python3 tools/run_frontier.py banks/evalw_numeric.jsonl out/responses.jsonl --limit 25
	python3 tools/grade_public.py banks/evalw_numeric.jsonl out/responses.jsonl --pretty
