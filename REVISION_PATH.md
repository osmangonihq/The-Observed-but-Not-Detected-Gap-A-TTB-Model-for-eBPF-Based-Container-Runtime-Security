# REVISION_PATH.md — critical path to a submittable manuscript

**Scope rule applied:** B1–B9 are *submission* blockers. Polishing, front matter and archival work are *acceptance* blockers and are deliberately kept off the critical path. Hours are one-author planning estimates (not sourced metrics).

## Week 1 — make the claims internally true

| B-id | Action | Exact location | Hours | Done when… | Blocks |
|---|---|---|---:|---|---|
| B4 | Replace stale counts: 91→87 files, "200 synthetic events"→175 analysed, "two empirical studies"→three, remove §6.1 claim "we do not execute exploits, install agents" | §6.1 Setup; §1 Introduction (contributions); Abstract; §8 Conclusion | 1.5 | No occurrence of 91/200 in results claims; §6.1 describes static, differential and live studies | Submission |
| B3 | Replace "Escape succeeded: YES" with "Primitive executed: yes — full escape chain not demonstrated"; make same qualification in prose | Table 11, "Escape succeeded" column (renamed); §6.4 paragraph beginning "The decisive rows"; Abstract if it says "escapes succeeded" | 2 | No row claims a completed escape; host-config writes described as primitives | Submission |
| B7 | Delete "post-exec capset" row's "tool syntax failure" result; reword "Fixed alert: YES (stale uid)" → "Alert fired; attribute stale (uid 1000)"; pin Tracee to image digest, not `latest` | Table 11 rows; Table 13 "Version" column; §6.1 agent list | 2 | No failed harness run presented as a result; Tracee identified by digest | Submission |
| B2 | Define P1–P7 once in §6.4; reconcile NO / 423 / 827 by stating run, capture window and attribution rule for each table; derive counts from the existing captured logs only | §6.4; Tables 11, 12, 13 | 5 | A reader can map every alert count to one run and one denominator; no undefined identifiers | Submission |

## Week 2 — repair the model and the core finding

| B-id | Action | Exact location | Hours | Done when… | Blocks |
|---|---|---|---:|---|---|
| B1 | Split the two host-config rows out of G. §4.1 already excludes no-rule cases: reclassify core_pattern/modprobe writes as a **coverage** finding (no policy event was emitted), and keep the setuid/stale-uid case as the genuine **trust** finding (O=1 ∧ P=0). Add a short §6.2 "coverage gaps" paragraph and reframe §6.4 accordingly | §4.1 definition of G; new §6.2 sub-paragraph; §6.4 "decisive rows" paragraph; Table 11; Abstract | 7 | Paper never calls a coverage gap a trust gap; the central claim rests on the stale-uid case | Submission |
| B6 | Rewrite Proposition 1: remove "monotone"; argue asymmetry — if an adversary can mutate τ's input while leaving all other fields P reads unchanged, P's output is invariant under that mutation, so P cannot distinguish the benign-attribution event from the malicious one; the adversary chooses the mutation, hence an event exists with O=1 and P=0 | §4.1 Proposition 1 and proof sketch | 2 | No self-contradiction; word "monotone" absent | Submission |

## Week 3 — novelty, evidence hygiene, declarations of uncertainty

| B-id | Action | Exact location | Hours | Done when… | Blocks |
|---|---|---|---:|---|---|
| B9 | Add explicit differentiation from ImmuCheck (write-immutability prevention) and BPFence (formal BPF semantics + expressiveness comparison). Remove or demote ref [26] SSRN from evidence to contextual citation and mark "preprint, not peer-reviewed". Re-rate Table 14 cells with per-cell basis | §2.3 Related work; Abstract novelty sentence; References [26]; Table 14 | 4 | Novelty claim is comparative, not "first"; no unrefereed source used as evidence | Submission |
| B5 | Downgrade Tetragon TB-01 and TB-06 ratings in Table 14 from `yes` to `partial`, with basis: its own LSM alert carries uid=1000 for a uid-0 write (Figure 6) | Table 14 rating cells; §7.1 basis strings; Figure 6 caption | 3 | Table 14 no longer contradicts Figure 6 | Submission |
| B8 | Replace "zero false positives over 2,032 events" with "0/2032; 95% upper bound 0.15% (rule of three)"; call the workload a short benign smoke test, not a workload; report overhead as raw ranges and explicitly state n=3 cannot establish 0.6% | §7.2 False-positive validity; §6.4 overhead paragraph | 2.5 | No unbounded zero-FP claim; no inferential claim from n=3 | Submission |

## Week 4 — coherence pass (still not polishing)

| Action | Exact location | Hours | Done when… | Blocks |
|---|---|---:|---|---|
| Read straight through against B1–B9; renumber Tables 1–15 after the B2 table split; verify every in-text Table/Figure reference | Whole manuscript | 2 | No orphan references; captions sequential | Submission |
| Re-run the consistency check on all result JSONs (audit, differential, statistics, live_testbed) | experiments/results/ | 1 | Every number quoted in text has a source file | Submission |

## Acceptance list — after submission, not on the critical path

- Shorten Abstract to ≤250 words once B4/B1/B9 text is final (Abstract).
- Remove duplicated in-image figure titles; caption carries the number (all 7 figures).
- Update Appendix A inventory to 7 figures and the live result files (`live_testbed.json`, `suid-race-events.json`, Falco/Tracee/Tetragon live logs).
- Expand "TTB-Audit" to "Telemetry-Trust Boundary Auditor" at first use (Abstract, §5).
- Add author block, ORCID, CRediT, competing interests, data availability, ethics/responsible disclosure, acknowledgements (front matter and declarations).
- Assign Zenodo DOI and insert in data-availability statement.
- If a reviewer demands more false-positive evidence: cheapest objection-killer is a **longer replay of the existing benign script on the same VM** (no new cluster, no new agent). Do not propose a new workload benchmark preemptively.

## Highest reviewer-risk reduction per hour

1. **B1 (7 h)** — the category error invalidates the paper's central definition; fixing it is the difference between a coherent paper and a rejected one.
2. **B2 (5 h)** — irreconcilable alert counts for a single run are an immediate credibility failure with reviewers who check tables.

## Not doing, and why

- **cgroup v1 `release_agent` live run** — requires a separate VM/kernel image; the paper does not need it once the claim is narrowed to cgroup v2.
- **Real argv-TOCTOU race demonstration** — needs custom timing/kernel support; weaken the claim to a documented risk plus the differential variant instead.
- **New detection mechanism** — would change the paper from measurement/tool to mechanism and add months of work; the LSM guard is sufficient as a demonstrated remediation.
- **Multi-kernel or multi-node matrix** — one kernel, three agents is enough to support the stated claim; more is a different paper.
- **ML/graph-based detector, operator survey, ImmuCheck replication, formal proof in Coq** — all out of scope for an audit/measurement paper.
