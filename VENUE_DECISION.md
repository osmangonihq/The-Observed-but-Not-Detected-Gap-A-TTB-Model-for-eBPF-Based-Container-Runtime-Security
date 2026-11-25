# VENUE_DECISION.md — one primary target, two fallbacks

**Decision: submit to Computers & Security (Elsevier).** Fallbacks, in order: (1) Journal of Systems Architecture, (2) Cybersecurity (Springer).

Scoring uses H/M/L judgements from the contribution profile in the brief. Decision-time and APC fields are **UNVERIFIED** — never asserted as facts; confirm on each publisher's Guide for Authors and APC page before submission.

| Journal | Scope fit (audit + measurement + tool) | Prestige | Time to first decision | Cost | Tolerance of single-kernel / single-site live study | Desk-reject risk: "no new mechanism" | Overall |
|---|---|---|---|---|---|---|---|
| **Computers & Security (Elsevier)** | **H** — applied security measurement and evaluation is core scope | M–H | UNVERIFIED (check journal page) | UNVERIFIED (check APC page) | **H** | **M–L** | **Best** |
| ACM TOPS | H | H | UNVERIFIED | UNVERIFIED | M | M–H | Viable but mechanism-averse |
| IEEE TDSC | H | H | UNVERIFIED | UNVERIFIED | M | **H** | Risky for this paper type |
| Journal of Systems Architecture | M–H | M | UNVERIFIED | UNVERIFIED | H | M–L | Fallback 1 |
| Cybersecurity (Springer) | M–H | M | UNVERIFIED | UNVERIFIED | H | M–L | Fallback 2 |
| Journal of Computer Security | M | M–H | UNVERIFIED | UNVERIFIED | M | M–H | Lower fit |
| Empirical Software Engineering (Springer) | H for tool/empirical work | H | UNVERIFIED | UNVERIFIED | M | M | Strong but competitive; would require a software-engineering framing |
| IEEE Access | M | L–M | UNVERIFIED | UNVERIFIED | H | L | Last resort only |

## Decision

The primary target is **Computers & Security**, because the contribution is explicitly an audit, a measurement study and a tool evaluation — not a new security mechanism — and that venue's readership is accustomed to empirical security evaluations with bounded, disclosed threats to validity. Fallback 1 is **Journal of Systems Architecture** if the first editor reads the work as systems measurement rather than security; fallback 2 is **Cybersecurity (Springer)** if the first venue considers the single-kernel live component too narrow. Expected total wall-clock time cannot be stated from verified data: **do not assert a number**; use only the journal's own published decision-time figures, and schedule for two decision cycles without quoting a figure externally. Strategy: post an arXiv preprint (cs.CR) at or just before submission — arXiv is not dual submission — and never submit to two journals simultaneously. Trigger a fallback on a desk rejection, or on a first decision whose scope letter explicitly asks for a new mechanism or multi-site evaluation. What the primary would desk-reject on today: a paper with an internal category error (B1), mutually irreconcilable alert counts (B2), an unaudited unrefereed source used as evidence (B9), and a central claim built on writes that never became policy events. Fix those three and it is submittable; fix B3–B8 as well and it is credible.

## FORMAT_UNVERIFIED items

- All submission-format specifics (abstract cap, Highlights count, reference style, section order, page limit) are **FORMAT_UNVERIFIED** for every journal above. Confirm in the official Guide for Authors. Safest defaults are given in STYLE_PLAYBOOK.md §(b)–(e).
- APC amounts, Open Access routes and "time to first decision" are **UNVERIFIED**; check publisher pages, do not rely on third-party summaries.
