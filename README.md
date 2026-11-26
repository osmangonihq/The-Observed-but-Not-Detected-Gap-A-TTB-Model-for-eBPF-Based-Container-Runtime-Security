# Research package — The Observed-but-Not-Detected Gap

**Manuscript:** *The Observed-but-Not-Detected Gap: A Detection-Trust Boundary Model for eBPF-Based Container Runtime Security*

**Primary target:** Computers & Security (Elsevier). See `VENUE_DECISION.md`.

## Deliverables

| Path | What it is |
|---|---|
| `manuscript.docx` / `manuscript.pdf` | **Final manuscript** (23 pages, 15 tables, 7 figures, 31 refs, 235-word abstract) |
| `REVISION_PATH.md`, `VENUE_DECISION.md`, `STYLE_PLAYBOOK.md` | Reviewer-style critical path, venue decision, journal style plan |
| `REVISIONS.md` | Closure record for reviewer blockers B1–B9 |
| `JOURNAL_ANALYSIS.md` | Supporting venue rationale |
| `auditor/` | TTB policy auditor; 12 unit tests |
| `experiments/policies/` | 87 effective frozen upstream policy files |
| `experiments/differential/` | event-level differential harness |
| `experiments/results/` | audit, differential, ablation, statistics, expressiveness, `live_testbed.json`, `suid-race-events.json`, raw Falco/Tracee/Tetragon logs |
| `experiments/make_figures.py` | regenerates Figures 1–7 with no in-image titles |
| `testbed/` | VM/kind manifests for Tetragon, Falco 0.45.2, Tracee, attacker and PoC pods |
| `figures/` | fig1–fig7, including the captured live snapshot |

## Evidence base

1. **Static audit:** 87 effective files / 296 rules; per-corpus gap fractions 13/23, 3/13, 1/19 with Wilson 95% CIs.
2. **Differential experiment:** 175 malicious events; alert rates fall under trust-anchor mutation.
3. **Live testbed (three agents):** KVM VM, kernel 6.14, kind/K8s; Tetragon v1.7.1, Falco 0.45.2, Tracee (pinned digest). Stock configurations gave no escape-specific alert for the two host-config writes (coverage gaps, §6.2). The setuid helper (P7) produced an alert carrying uid 1000 while the process was uid 0 at write time — the genuine O=1∧P=0 trust finding of §6.4. An LSM guard restored path-specific detection.
4. **False positives:** short benign smoke test, 2,032 events → 14 kprobe alerts, 0 LSM-guard alerts (95% upper bound 0.15%). Not a precision estimate.
5. **Signed model + mechanism:** predicate polarity, Proposition 2 (expressiveness limit), and DTB-Harden, whose event-time guards restored both host-config writes (0/2 -> 2/2).
6. **Formal + practical:** Proposition 1 (asymmetry of trust-bearing decisions), explicit soundness/completeness bounds, six-row practitioner checklist (Table 15).
6. **Epistemics:** adversary model, τ→mutation→effect table, anchor-blind selection, commit SHAs, access dates, per-cell evidence.

## Honest limits

cgroup v2 only (no `release_agent`); one kernel; short benign workload; n=3 overhead runs cannot support an inferential claim; BPFence and ref [26] marked as unrefereed preprints; no fabricated results.

## Reproduce

```bash
cd auditor && python3 -m unittest discover -s tests -v
python3 -m ttb_auditor.cli ../experiments/policies --json ../experiments/results/audit.json
cd ../experiments/differential && python3 run_experiment.py
cd .. && python3 ablation.py && python3 epistemics.py && python3 make_figures.py
```
Live setup details are in `testbed/` and `vm/images/`. The manuscript is the delivered DOCX.
