# Closure record for reviewer blockers B1–B9

| ID | Status | Where fixed in manuscript |
|---|---|---|
| B1 | Closed | §4.1 (G excludes coverage gaps; host-config writes named as coverage), new §6.2 "Coverage gaps" paragraph, §6.4 lead and decisive paragraphs, Table 11 caption, Abstract, Conclusion |
| B2 | Closed | §6.4 P1–P7 definition; "Alert-count convention" paragraph after Table 13; Tables 11–13 captions reconciled |
| B3 | Closed | Table 11 column renamed "Primitive executed" with qualified values; §6.4 and Abstract reworded |
| B4 | Closed | 87 effective files, 175 malicious events, three studies throughout; §6.1 static-only claim removed; Appendix A inventory updated |
| B5 | Closed | Table 14 Tetragon TB-01 and TB-06 downgraded to `partial` with Figure 6 basis |
| B6 | Closed | §4.1 Proposition 1 rewritten without "monotone"; asymmetry/adversary-chooses argument |
| B7 | Closed | Table 11 capset row marked "harness limitation; excluded"; "Fixed alert" cell reworded; Table 13 Tracee pinned to digest c83ce5aa |
| B8 | Closed | 0/2032 with 95% upper bound 0.15%; short benign smoke test; overhead reported as overlapping raw ranges with no inferential claim |
| B9 | Closed | §2.3 differentiation from ImmuCheck [24] and BPFence [31]; ref [26] marked preprint/context only; novelty language removed from Table 1 caption and §2.3 |

## Polish applied

- Abstract 235 words, fits page 1.
- Highlights (5) added; all 7 figures regenerated with **no in-image titles**.
- Appendix A lists 7 figures and all live result files.
- "TTB-Audit" expanded at first use.
- Title-page ORCID placeholder; Declarations section with CRediT, competing interests, data availability, ethics/responsible disclosure, ORCID and acknowledgements.
- Zenodo DOI placeholder retained in data-availability statement.

## Not applied (journal-side, post-acceptance)

- Table 14 moved to appendix and table merges: left in place to avoid renumbering risk; implement at proof stage if the journal requires fewer main tables.
- Real argv-TOCTOU race, cgroup v1 `release_agent`, multi-kernel matrix: out of scope, disclosed in §7.2.
