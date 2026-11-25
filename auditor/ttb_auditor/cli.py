"""Command-line entry point for the TTB policy auditor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import audit_directory, audit_policy_file
from .report import summary_table, write_json, write_markdown, to_dict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ttb-audit",
        description="Audit eBPF runtime-security policies for Detection-Trust Boundary gaps.",
    )
    p.add_argument("path", type=Path, help="Policy file or directory of policy files")
    p.add_argument("--json", type=Path, help="Write full machine-readable report to this path")
    p.add_argument("--markdown", type=Path, help="Write human-readable report to this path")
    p.add_argument("--quiet", action="store_true", help="Suppress stdout summary")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = args.path
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 2

    if path.is_dir():
        results = audit_directory(path)
    else:
        tool, audits = audit_policy_file(path)
        if not audits:
            print(f"error: no supported rules found in {path}", file=sys.stderr)
            return 2
        from .model import ToolAudit
        from .corpus import TECHNIQUES
        verdicts = []
        for technique in TECHNIQUES:
            covering = [ra for ra in audits if ra.rule.observables & set(technique.observables)]
            from .model import TechniqueVerdict
            verdicts.append(TechniqueVerdict(technique=technique, covering_rules=covering))
        results = {tool: ToolAudit(tool, [str(path)], audits, verdicts)}

    if args.json:
        write_json(results, args.json)
    if args.markdown:
        write_markdown(results, args.markdown)
    if not args.quiet:
        print(summary_table(results))
        print()
        print(json.dumps(to_dict(results)["corpus"], indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
