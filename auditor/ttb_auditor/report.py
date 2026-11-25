"""Machine-readable and human-readable report renderers."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .model import ToolAudit, TrustClass
from .corpus import corpus_summary


def to_dict(results: dict[str, ToolAudit]) -> dict:
    out: dict = {
        "schema": "ttb-audit/1.0",
        "corpus": corpus_summary(),
        "tools": {},
    }
    for tool, audit in results.items():
        out["tools"][tool] = {
            "source_files": [Path(p).name for p in audit.source_files],
            "rule_count": len(audit.rule_audits),
            "finding_count": len(audit.findings),
            "mean_tds": round(audit.mean_tds, 4),
            "gap_ratio": round(audit.gap_ratio, 4),
            "counts": {
                "detected": audit.detected_count,
                "observed_not_detected": audit.gap_count,
                "no_rule": audit.uncovered_count,
            },
            "trust_class_counts": audit.class_counts(list(TrustClass)),
            "findings": [f.as_dict() for f in audit.findings],
            "techniques": [
                {
                    "id": v.technique.id,
                    "name": v.technique.name,
                    "classification": v.classification,
                    "best_tds": round(v.best_tds, 4) if v.best_tds is not None else None,
                    "covering_rules": [ra.rule.name for ra in v.covering_rules][:6],
                    "triggered_checks": (
                        sorted({
                            f.check_id for f in min(
                                v.covering_rules, key=lambda ra: ra.tds
                            ).findings
                        })
                        if v.covering_rules else []
                    ),
                }
                for v in audit.verdicts
            ],
        }
    return out


def write_json(results: dict[str, ToolAudit], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_dict(results), indent=2, ensure_ascii=False), encoding="utf-8")


def write_markdown(results: dict[str, ToolAudit], path: Path) -> None:
    lines: list[str] = [
        "# Telemetry-Trust Boundary — policy audit report",
        "",
        "Static analysis of upstream policy files. No live exploitation is implied.",
        "",
    ]
    for tool, audit in results.items():
        lines += [
            f"## {tool}",
            "",
            f"- Policy files analysed: {len(audit.source_files)}",
            f"- Normalized rules: {len(audit.rule_audits)}",
            f"- Findings: {len(audit.findings)}",
            f"- Mean Trust Dependency Score: {audit.mean_tds:.3f}",
            f"- Gap ratio (observed-but-not-detected / covered): {audit.gap_ratio:.1%}",
            "",
            "| Technique | Classification | Best TDS | Covering rules |",
            "|---|---|---:|---|",
        ]
        for v in audit.verdicts:
            rules = ", ".join(ra.rule.name for ra in v.covering_rules[:3]) or "—"
            tds = f"{v.best_tds:.2f}" if v.best_tds is not None else "—"
            lines.append(
                f"| {v.technique.id} {v.technique.name} | {v.classification} | "
                f"{tds} | {rules} |"
            )
        lines += ["", "### Trust-anchor distribution", ""]
        for cls, count in audit.class_counts(list(TrustClass)).items():
            lines.append(f"- `{cls}`: {count}")
        lines.append("")

        top = sorted(
            audit.rule_audits, key=lambda ra: ra.tds, reverse=True
        )[:10]
        lines += ["### Highest-trust-dependency rules", ""]
        for ra in top:
            checks = ", ".join(sorted({f.check_id for f in ra.findings}))
            lines.append(
                f"- `{ra.rule.name}` — TDS {ra.tds:.2f} [{checks or 'none'}] — "
                f"{Path(ra.rule.source_file).name}"
            )
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def summary_table(results: dict[str, ToolAudit]) -> str:
    rows = [
        "| Tool | Rules | Findings | Mean TDS | Detected | Observed-not-detected | No rule | Gap ratio |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tool, audit in results.items():
        rows.append(
            f"| {tool} | {len(audit.rule_audits)} | {len(audit.findings)} | "
            f"{audit.mean_tds:.3f} | {audit.detected_count} | {audit.gap_count} | "
            f"{audit.uncovered_count} | {audit.gap_ratio:.1%} |"
        )
    return "\n".join(rows)
