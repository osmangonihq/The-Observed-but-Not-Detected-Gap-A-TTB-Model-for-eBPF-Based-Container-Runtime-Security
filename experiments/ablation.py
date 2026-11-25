"""Sensitivity analysis for the Trust Dependency Score weights and threshold."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "auditor"))

from ttb_auditor.engine import audit_directory  # noqa: E402
from ttb_auditor.model import TRUST_WEIGHTS  # noqa: E402

OUT = ROOT / "experiments" / "results" / "ablation.json"
POLICIES = ROOT / "experiments" / "policies"
THRESHOLDS = [0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50]
SEV = {"critical": 1.0, "high": 1.0, "medium": 0.4, "low": 0.2}


def tds(ra, scale: dict | None = None) -> float:
    total = 0.0
    for f in ra.findings:
        w = TRUST_WEIGHTS[f.trust_class]
        if scale and f.check_id in scale:
            w *= scale[f.check_id]
        total += w * SEV.get(f.severity, 0.4)
    return min(1.0, total)


def main() -> None:
    audits = audit_directory(POLICIES)
    result: dict = {"schema": "ttb-ablation/1.0", "thresholds": THRESHOLDS, "tools": {}}

    for tool, audit in audits.items():
        series = {}
        for threshold in THRESHOLDS:
            gaps = detected = 0
            for v in audit.verdicts:
                covering = v.covering_rules
                if not covering:
                    continue
                robust = [
                    ra for ra in covering
                    if not any(f.severity in ("critical", "high") for f in ra.findings)
                    and tds(ra) < threshold
                ]
                if robust:
                    detected += 1
                else:
                    gaps += 1
            series[str(threshold)] = {
                "detected": detected,
                "gaps": gaps,
                "gap_ratio": round(gaps / (gaps + detected), 4) if gaps + detected else 0.0,
            }
        result["tools"][tool] = series

    # Additional single-check ablations at the canonical threshold.
    for check in ["TB-01", "TB-02", "TB-03", "TB-04", "TB-05", "TB-06"]:
        per_check = {}
        for tool, audit in audits.items():
            gaps = detected = 0
            for v in audit.verdicts:
                if not v.covering_rules:
                    continue
                robust = []
                for ra in v.covering_rules:
                    findings = [f for f in ra.findings if f.check_id != check]
                    high = any(f.severity in ("critical", "high") for f in findings)
                    score = min(1.0, sum(
                        TRUST_WEIGHTS[f.trust_class] * SEV.get(f.severity, 0.4)
                        for f in findings
                    ))
                    if not high and score < 0.25:
                        robust.append(ra)
                if robust:
                    detected += 1
                else:
                    gaps += 1
            per_check[tool] = round(gaps / (gaps + detected), 4) if gaps + detected else 0.0
        result[f"without_{check}"] = per_check

    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {OUT}")
    print("\nThreshold sweep (gap ratio):")
    print("t      " + "".join(f"{t:>12}" for t in audits))
    for th in THRESHOLDS:
        print(f"{th:<7}" + "".join(
            f"{result['tools'][t][str(th)]['gap_ratio']:>11.1%} " for t in audits
        ))
    print("\nRemove one check (gap ratio at t=0.25):")
    for check in ["TB-01", "TB-02", "TB-03", "TB-04", "TB-05", "TB-06"]:
        print(f"  without {check}: " + "  ".join(
            f"{t}={result[f'without_{check}'][t]:.1%}" for t in audits
        ))


if __name__ == "__main__":
    main()
