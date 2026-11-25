# Results files

Machine-readable single JSON documents:
- `audit.json` — static policy audit (regenerable with `ttb_auditor`)
- `differential.json` — 175-event differential experiment
- `ablation.json` — TDS threshold and single-check ablation
- `statistics.json` — Wilson 95% confidence intervals
- `expressiveness.json` — per-cell expressiveness ratings
- `live_testbed.json` — environment record, primitive triple and measured counts
- `policy_manifest.json` — provenance of the 91 downloaded policy files

Newline-delimited JSON logs (one JSON object per line; parse with a line-by-line reader, not `json.load`):
- `attack-file-events.jsonl` — Tetragon capture, attack run (629 events)
- `tetragon-live.jsonl` — Tetragon capture, three-agent run (587 events)
- `falco-live.log` — Falco alerts, three-agent run (3 events)
- `tracee-live.log` — Tracee events, three-agent run (10 events)

Abridged evidence:
- `suid-race-events-extract.jsonl` — the two captured events shown in Figure 6, transcribed field-for-field. The full VM trace was lost when the testbed disk was reclaimed; the extract is labelled as such and is not presented as a complete log.
