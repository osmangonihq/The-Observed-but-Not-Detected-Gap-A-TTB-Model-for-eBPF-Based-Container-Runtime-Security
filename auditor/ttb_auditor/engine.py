"""Audit engine: apply checks, score rules, classify escape techniques."""

from __future__ import annotations

from pathlib import Path

from .checks import CHECKS
from .corpus import TECHNIQUES
from .model import RuleAudit, TechniqueVerdict, ToolAudit
from .parsers import parse_file


def audit_policy_file(path: Path) -> tuple[str, RuleAudit | list[RuleAudit]]:
    """Audit one policy file; returns (tool, list-of-rule-audits)."""
    tool, rules = parse_file(path)
    audits = []
    for rule in rules:
        findings = []
        for check in CHECKS:
            findings.extend(check(rule))
        audits.append(RuleAudit(rule=rule, findings=findings))
    return tool, audits


def audit_directory(policies_dir: Path) -> dict[str, ToolAudit]:
    """Audit every policy file under *policies_dir* recursively."""
    buckets: dict[str, list[RuleAudit]] = {}
    sources: dict[str, list[str]] = {}

    for path in sorted(policies_dir.rglob("*")):
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            continue
        tool, audits = audit_policy_file(path)
        if tool == "unknown" or not audits:
            continue
        buckets.setdefault(tool, []).extend(audits)
        sources.setdefault(tool, []).append(str(path))

    results: dict[str, ToolAudit] = {}
    for tool, audits in buckets.items():
        verdicts = []
        for technique in TECHNIQUES:
            covering = [
                ra for ra in audits
                if ra.rule.observables & set(technique.observables)
            ]
            verdicts.append(TechniqueVerdict(technique=technique, covering_rules=covering))
        results[tool] = ToolAudit(
            tool=tool,
            source_files=sources[tool],
            rule_audits=audits,
            verdicts=verdicts,
        )
    return results
