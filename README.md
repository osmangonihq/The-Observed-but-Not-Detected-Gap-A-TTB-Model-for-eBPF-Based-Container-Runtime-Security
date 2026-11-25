# The Observed-but-Not-Detected Gap

**Paper:** *The Observed-but-Not-Detected Gap: A Detection-Trust Boundary Model for eBPF-Based Container Runtime Security*

This repository contains the full reproducible research package: the manuscript, a static policy auditor, a synthetic differential harness, a curated escape-technique corpus, a live three-agent testbed (manifests and PoC sources), all result files, and the reviewer-style revision/venue documents.

## Contents

| Path | What it is |
|---|---|
| `manuscript.docx` / `manuscript.pdf` | **Final manuscript** (23 pages A4, 16 tables, 7 figures, 31 refs) |
| `REVISION_PATH.md` | Week-by-week critical path, B1–B9, submission vs acceptance |
| `VENUE_DECISION.md` | Scored venue table; primary target **Computers & Security** |
| `STYLE_PLAYBOOK.md` | Section-by-section writing plan, abstract/highlights, declarations, cover letter |
| `TOPTIER_READINESS.md` | Honest assessment of what remains for TDSC/TOPS |
| `REVISIONS.md` | Closure record for reviewer blockers B1–B9 |
| `JOURNAL_ANALYSIS.md` | Supporting venue rationale |
| `auditor/` | DTB policy auditor (12 unit tests) |
| `experiments/policies/` | 87 effective frozen upstream policy files (Falco/Tetragon/Tracee) |
| `experiments/differential/` | Event-level differential harness |
| `experiments/results/` | Audit, differential, ablation, statistics, expressiveness, `live_testbed.json`, `engine_differential.json`, abridged evidence extract and raw NDJSON agent logs |
| `experiments/make_figures.py` | Regenerates Figures 1–7 (captions carry numbering) |
| `testbed/manifests/`, `testbed/poc/` | Kubernetes manifests for Tetragon, Falco 0.45.2, Tracee, workload/PoC pods |
| `figures/` | fig1–fig7 |
| `vm/README.md` | Sanitized testbed setup notes (no credentials or large images) |

## Evidence base

1. **Static audit:** 87 effective files / 296 rules; per-corpus gap fractions 13/23, 3/13, 1/19 with Wilson 95% CIs.
2. **Differential experiment:** 175 malicious events; alert rates fall under trust-anchor mutation in the abstract interpreter.
3. **Engine-level calibration (§6.5):** six primitives × two conditions with real Falco/Tetragon/Tracee agents. Falco alerted 6/6 on renamed binaries — the opposite direction to the interpreter — which the paper diagnoses as an anchor-polarity defect.
4. **Live testbed (three agents):** kernel 6.14, cgroup v2, kind/K8s. The setuid helper (P7) produced an alert carrying uid 1000 while the process was uid 0 at write time — the genuine O=1∧P=0 trust finding.
5. **False positives:** short benign smoke test, 2,032 events → 14 kprobe alerts, 0 LSM-guard alerts (95% upper bound 0.15%). Not a precision estimate.
6. **Formal + practical:** Proposition 1 (asymmetry of trust-bearing decisions), explicit soundness/completeness bounds, six-row practitioner checklist.

## Honest limits

cgroup v2 only (no `release_agent`); one kernel; short benign workload; n=3 overhead runs cannot support an inferential claim; the full raw VM trace was lost and Figure 6 uses an explicitly abridged extract; preprints are marked as such; no fabricated results. See `TOPTIER_READINESS.md`.

## Reproduce

```bash
cd auditor && python3 -m unittest discover -s tests -v
python3 -m ttb_auditor.cli ../experiments/policies --json ../experiments/results/audit.json
cd ../experiments/differential && python3 run_experiment.py
cd .. && python3 ablation.py && python3 epistemics.py && python3 make_figures.py
```

Large VM disk images and machine-specific login helpers are intentionally excluded. Set your own VM password if you reproduce the live study; none is stored here.
