# STYLE_PLAYBOOK.md — Computers & Security (Elsevier)

All journal-format rules below are **FORMAT_UNVERIFIED** unless the brief supplied them. Safest defaults are given; confirm in the Elsevier Guide for Authors for Computers & Security.

## (a) Structural map — what belongs where

**Lead with the measurement, not the mechanism.** Keep order: Introduction → Background/Related work → DTB model → Auditor → Evaluation (audit → differential → live) → Discussion → Conclusion.

- **§1 Introduction.** Open with the observation/decision asymmetry, then the three contributions (audit, differential, live three-agent). State the novelty sentence from (b) here.
- **§2.3 Related work.** Add the ImmuCheck/BPFence comparison paragraph (B9). Keep positioning Table 1.
- **§4.1.** Keep G, but append the corrected Proposition 1 (B6). Add one sentence that coverage gaps (O=0) are *outside* G and are reported separately.
- **New §6.2 sub-paragraph — "Coverage gaps".** This is where the core_pattern/modprobe writes move under B1. They are a coverage finding, not a trust finding.
- **§6.4 Live study.** Define P1–P7 once (B2); report the stale-uid case as the genuine G instance; move the three-agent comparison table (current Table 13) here.
- **Move to appendix:** Table 14 (expressiveness ratings with per-cell evidence). **Merge:** current Tables 6+7 (corpus + provenance) into one; current Tables 9+10 (differential rates + aggregate) if space is tight. **Keep as main:** positioning, anchor taxonomy, per-corpus verdicts, live triple, three-agent comparison.
- **Must die:** duplicate in-image figure titles; "escape succeeded: YES"; "zero false positives"; "no new mechanism" hedge — replace with a precise scope statement.

## (b) Front matter spec

- **Title.** FORMAT_UNVERIFIED (length convention). Safest default: ≤18 words, statement-style, subtitle only if allowed. Current title is acceptable after B3 ("escapes"→primitives if needed).
- **Abstract.** FORMAT_UNVERIFIED (cap). Brief-supplied target: ≤250 words. Model abstract (≈230 words, built only from claims that survive B1–B9):

> Kernel-level eBPF sensors are often described as providing complete syscall visibility, yet a visible escape primitive may still produce no alert. We formalise this observation-to-decision gap as the Detection-Trust Boundary: detection equals observation conjoined with a policy decision, and the latter delegates to trust anchors — launch-time privilege metadata, mutable allowlists, inferred fields, binary names, single-layer hooks and exec-time credential snapshots — that a privileged in-container workload can invalidate. We present a six-class anchor taxonomy, a Trust Dependency Score and TTB-Audit, a static auditor for Falco, Tetragon and Tracee policies. Across 87 upstream policy files (296 rules) and 25 escape techniques, the fraction of covered techniques that are observed-but-not-detected is 13/23 (95% CI 36.8–74.4) for Falco, 3/13 for Tetragon and 1/19 for Tracee. A 175-event differential experiment shows alert rates falling under trust-anchor mutations. Because these are policy-level results, we deployed three agents — Tetragon v1.7.1, Falco 0.45.2 and Tracee — in a KVM/kind testbed. Stock configurations observed the workload but produced no escape-specific alert for two successful host-config writes; a two-rule LSM guard restored detection, and a setuid helper exposed an alert whose uid was the exec-time snapshot (1000) while the process was uid 0 at write time. The benign smoke test yielded no LSM-guard alerts in 2,032 events (95% upper bound 0.15%). Detection trustworthiness is bounded by its weakest delegated input; we provide a practitioner checklist.

- **Highlights** (Elsevier convention, ≤85 characters each, from brief):
  1. `eBPF sensors can observe a syscall that its policy declines to alert on`
  2. `Audit of 87 upstream policies across Falco, Tetragon and Tracee`
  3. `Gap fractions 13/23, 3/13, 1/19 with Wilson 95% confidence intervals`
  4. `Three live agents: stock policies missed two host-config writes`
  5. `An LSM guard restored detection; stale-uid alerts exposed the trust gap`
- **Keywords (6):** eBPF; container escape; runtime security; policy audit; trust boundary; observability.
- **Novelty sentence:** "Unlike ImmuCheck, which prevents escapes through selective path immutability, and BPFence, which formalises eBPF program semantics, this paper audits the trust inputs of shipped detection policies and measures observation-to-decision divergence on three deployed agents."

## (c) Tables and figures

- **Count.** FORMAT_UNVERIFIED. Safest default: ≤10 main tables; move Table 14 to appendix, merge 6+7 and 9+10 as above. Seven figures are acceptable; remove the in-image titles from all seven so each caption alone carries the number and description.
- **Each main table must show:** its denominator; its source result file; whether it is static, differential or live; and a one-line caption stating what the reader should conclude. Tables 11–13 must share one alert-count convention after B2.
- **Caption rule:** `Table N. <decision sentence>. <denominator/source>.` No title line inside the PNG.

## (d) Citations and references

- **Style.** FORMAT_UNVERIFIED. Safest default: numbered `[1]` in Elsevier Vancouver style; confirm in Guide for Authors.
- **Software repositories:** cite with repository, commit SHA and access date (already present for the three upstream corpora).
- **Preprints:** mark explicitly "preprint, not peer-reviewed" and **never** use as sole evidence for a factual claim. Ref [26] (SSRN) must be demoted to context or removed (B9).
- **Vendor documentation:** cite as primary-source documentation with URL and access date; this is legitimate evidence for *what the tool claims*, not for *how it behaves*.

## (e) Mandatory declarations

CRediT author contributions; competing interests; data/artifact availability (Zenodo DOI placeholder until assigned); ethics and responsible disclosure; ORCID iD; acknowledgements. These are acceptance blockers, not critical-path items, except that the author block must be present in whatever form the submission system requires (FORMAT_UNVERIFIED at first submission).

## (f) Language register — ten red-pen rewrites

1. "This proves the writes were kernel-visible." → "The LSM alert shows the writes reached a kernel hook."
2. "The gap is large." → "The observed gap fractions were 13/23, 3/13 and 1/19."
3. "Zero false positives." → "No LSM-guard alerts occurred in 2,032 events (95% upper bound 0.15%)."
4. "Escape succeeded: YES" → "Primitive executed; no full escape chain demonstrated."
5. "Complete visibility" (our voice) → "vendor-claimed visibility".
6. "Our novel model" → "Our model".
7. "Clearly, the policy is at fault" → "The policy condition did not include this path."
8. "Significant degradation" → "Alert rate fell from 92% to 36% in this experiment."
9. "The fix works" → "The added guard produced four path-specific alerts in this run."
10. "Guarantees detection" → "Was observed to alert under the tested conditions."

**Banned:** proves, complete, novel, clearly, obviously, significant (without statistic), guarantee, zero false positives, escape succeeded.

## (g) Paragraph templates

**Abstract:** [Context sentence: claimed visibility vs observed behaviour.] [Gap definition and its formal name.] [What we built: taxonomy, score, auditor.] [Audit result with denominators and CIs.] [Differential result.] [Live result with agents and the established limitation.] [Concluding scope statement.]

**Introduction:** ¶1 asymmetry and motivating example. ¶2 why existing tool/mechanism work does not resolve it. ¶3 three contributions with exact artefacts. ¶4 novelty sentence differentiating ImmuCheck and BPFence. ¶5 roadmap.

**Conclusion:** ¶1 restate the model in one sentence. ¶2 what was measured and where (three studies, exact counts). ¶3 what the live study established and its boundary. ¶4 practitioner implication. ¶5 limitations and one forward-looking sentence.

## (h) Submission-day checklist and cover letter

Checklist: B1–B9 closed; tables sequential and denominators consistent; figure titles removed from images; abstract ≤250; Highlights ≤85 chars; keywords 4–6; ref [26] demoted; declarations present; artifacts packaged; arXiv posted; single-journal submission confirmed.

**Cover letter (≈150 words):**

> Dear Editor, We submit a measurement and tool paper on the gap between kernel-level observation and policy-level alerting in eBPF container security. We formalise the Detection-Trust Boundary and present a six-class trust-anchor taxonomy, a Trust Dependency Score, and a reproducible static auditor for Falco, Tetragon and Tracee policies. Across 87 upstream policy files and 296 rules we report per-corpus gap fractions with Wilson confidence intervals; a 175-event differential experiment measures alert degradation under trust-anchor mutation. We further deployed three live agents in a KVM/kind testbed: stock configurations observed seven primitives but produced no escape-specific alert for two host-config writes, a two-rule LSM guard restored detection, and a setuid helper exposed an alert carrying an exec-time uid. We position the work against ImmuCheck and BPFence: we audit the trust inputs of shipped policies rather than proposing path immutability or formalising BPF semantics. Computers & Security is a strong fit because the contribution is an empirical evaluation with explicit limitations. Artifacts, raw traces and PoC sources are included. Yours sincerely, [Author]

## FORMAT_UNVERIFIED register

- Abstract word cap, Highlights count/character limit, title length, reference style, table/figure limits, section order, declaration placement — all **FORMAT_UNVERIFIED**; safe defaults above; confirm in the Elsevier Guide for Authors.
- Only the Highlights (3–5, ≤85 characters) and keyword count (4–6) were supplied by the brief; journal-specific confirmation still required.
