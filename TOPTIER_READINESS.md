# Top-tier readiness assessment

## Verdict

The manuscript is submittable now to **Computers & Security** (Elsevier). It is **not** yet competitive for IEEE TDSC or ACM TOPS.

## What the paper has

- A formal Detection-Trust Boundary model with Proposition 1 (asymmetry of trust-bearing decisions).
- A static audit of 87 upstream policy files / 296 rules with Wilson 95% CIs.
- A 175-event differential experiment over an abstract interpreter of extracted anchors.
- A live three-agent KVM/kind testbed with seven labelled and six executed primitives, plus a setuid-helper stale-uid demonstration.
- An engine-level calibration (§6.5) using real Falco, Tetragon and Tracee.
- A demonstrated two-rule LSM remediation with a bounded false-positive smoke test.

## Why it is not top-tier (yet)

1. **No new security mechanism.** The remediation applies an existing LSM hook.
2. **Proposition 1 is structural**, close to definitional; it will not carry a theory-heavy venue.
3. **Engine-level evidence is narrow and partly negative.** The interpreter's TB-04 polarity was wrong for live Falco; we diagnose this and specify a remedy (annotate anchor polarity and recompute), but do not implement it because six primitives on one engine cannot calibrate it.
4. **Single kernel, cgroup v2 only, ~40 s benign workload, one cluster, abridged raw trace.**

## The minimum work that changes the verdict

A full 25-technique × 2-condition engine-level experiment with purpose-built policies per engine, plus a formal expressiveness result showing that a class of policies cannot distinguish stale attributes without event-time revalidation. That is a different, larger paper. We did not fabricate results to bridge this gap.

## Decision

Submit to Computers & Security with the arXiv preprint posted at the same time; do not dual-submit. Retarget to TDSC/TOPS only after the additional mechanism and formal work above.
