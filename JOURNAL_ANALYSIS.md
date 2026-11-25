# Venue rationale (summary)

The primary target is **Computers & Security (Elsevier)**; fallbacks are **Journal of Systems Architecture** then **Cybersecurity (Springer)**. The full scored comparison and submission strategy are in `VENUE_DECISION.md`.

## Why this venue

The contribution is an audit, a measurement study and a tool evaluation — not a new security mechanism. TDSC and ACM TOPS are more likely to raise a "no new mechanism" objection; Computers & Security routinely publishes applied security evaluations with bounded, disclosed threats to validity. The single-kernel, three-agent live study is adequate for this venue when framed as a bounded demonstration rather than a prevalence claim.

## What would have caused desk rejection before revision

- **B1:** the paper classified the two host-config writes as trust-gap instances although no policy event existed (a coverage gap). Fixed in §4.1, new §6.2 paragraph, §6.4 and Table 11.
- **B2:** Tables 11/12/13 gave irreconcilable alert counts (NO / 423 / 827) and used undefined P1/P2. Fixed with a P1–P7 definition and a capture-convention paragraph.
- **B9:** an unrefereed SSRN preprint was used as evidence and novelty was asserted against work that overlaps the model. Fixed by demoting [26], adding BPFence [31] as a clearly marked preprint, and an explicit differentiation paragraph.

## Cover letter and timing

Use the 150-word cover letter in `STYLE_PLAYBOOK.md` §(h). Post an arXiv preprint (cs.CR) at submission; do not dual-submit. Do not assert journal decision times, impact factors or APCs — all such figures are marked UNVERIFIED in `VENUE_DECISION.md` and must be checked on the publisher's site.
