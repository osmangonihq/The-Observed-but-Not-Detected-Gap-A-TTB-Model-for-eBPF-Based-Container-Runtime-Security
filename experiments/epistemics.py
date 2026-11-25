"""Compute Wilson 95% CIs and provenance statistics for the upgrade."""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "experiments" / "results"
Z = 1.959963984540054


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    h = (Z / d) * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    return max(0.0, c - h), min(1.0, c + h)


def main() -> None:
    audit = json.loads((RES / "audit.json").read_text())
    diff = json.loads((RES / "differential.json").read_text())
    out: dict = {"schema": "ttb-statistics/1.0", "ci_method": "Wilson score, 95%", "static": {}, "differential": {}}

    for tool, a in audit["tools"].items():
        c = a["counts"]
        covered = c["detected"] + c["observed_not_detected"]
        lo, hi = wilson(c["observed_not_detected"], covered)
        out["static"][tool] = {
            "robustly_covered": c["detected"],
            "gap": c["observed_not_detected"],
            "no_rule": c["no_rule"],
            "covered_denominator": covered,
            "gap_fraction": c["observed_not_detected"] / covered if covered else 0.0,
            "gap_ci95": [round(lo, 4), round(hi, 4)],
        }

    for tool, a in diff["tools"].items():
        variants = {}
        for v, d in a["by_variant"].items():
            lo, hi = wilson(d["fired"], d["events"])
            variants[v] = {
                "fired": d["fired"], "n": d["events"],
                "rate": d["rate"], "ci95": [round(lo, 4), round(hi, 4)],
            }
        o = a["overall"]
        prec_lo, prec_hi = wilson(o["tp"], o["tp"] + o["fp"])
        rec_lo, rec_hi = wilson(o["tp"], o["tp"] + o["fn"])
        out["differential"][tool] = {
            "by_variant": variants,
            "precision_ci95": [round(prec_lo, 4), round(prec_hi, 4)],
            "recall_ci95": [round(rec_lo, 4), round(rec_hi, 4)],
        }

    (RES / "statistics.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("Wrote statistics.json")
    for tool in out["static"]:
        s = out["static"][tool]
        print(f"{tool}: gap {s['gap']}/{s['covered_denominator']} = "
              f"{s['gap_fraction']:.1%} [95% CI {s['gap_ci95'][0]:.1%}, {s['gap_ci95'][1]:.1%}]")


if __name__ == "__main__":
    main()
