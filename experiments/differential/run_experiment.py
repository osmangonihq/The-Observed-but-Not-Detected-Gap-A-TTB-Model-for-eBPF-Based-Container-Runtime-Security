"""Run the event-level differential experiment and write results JSON."""

from __future__ import annotations

import json
from pathlib import Path

from events import VARIANTS, generate_events
from interpreter import detect, load_rules

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "experiments" / "policies"
OUT = ROOT / "experiments" / "results" / "differential.json"

MALICIOUS_VARIANTS = [v for v in VARIANTS if v != "benign-lookalike"]


def metrics(fired_malicious, fired_benign, total_malicious, total_benign):
    tp = fired_malicious
    fn = total_malicious - fired_malicious
    fp = fired_benign
    tn = total_benign - fired_benign
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
    }


def main() -> None:
    events = generate_events()
    rules = load_rules(POLICIES)
    results: dict = {
        "schema": "ttb-differential/1.0",
        "description": (
            "Abstract interpretation of trust anchors over synthetic events. "
            "Not a vendor engine; no live exploitation."
        ),
        "event_count": len(events),
        "variant_count": len(VARIANTS),
        "technique_count": len({e.technique_id for e in events}),
        "tools": {},
    }

    for tool, trules in rules.items():
        fired_by_event: dict[str, list[str]] = {}
        for ev in events:
            fired_by_event[ev.id] = detect(trules, ev)

        by_variant: dict[str, dict] = {}
        for variant in VARIANTS:
            subset = [e for e in events if e.variant == variant]
            fired = sum(bool(fired_by_event[e.id]) for e in subset)
            by_variant[variant] = {
                "events": len(subset),
                "fired": fired,
                "rate": round(fired / len(subset), 4) if subset else 0.0,
            }

        malicious = [e for e in events if e.malicious]
        benign = [e for e in events if not e.malicious]
        tp = sum(bool(fired_by_event[e.id]) for e in malicious)
        fp = sum(bool(fired_by_event[e.id]) for e in benign)
        m = metrics(tp, fp, len(malicious), len(benign))

        baseline_rate = by_variant["baseline"]["rate"]
        anchor_drop = {
            v: round(baseline_rate - by_variant[v]["rate"], 4)
            for v in MALICIOUS_VARIANTS if v != "baseline"
        }

        results["tools"][tool] = {
            "rules": len(trules),
            "by_variant": by_variant,
            "anchor_drop": anchor_drop,
            "overall": m,
            "fired_by_event": fired_by_event,
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
    print(f"Events: {results['event_count']} "
          f"({results['technique_count']} techniques x {results['variant_count']} variants)")
    print()
    header = f"{'Variant':<24}" + "".join(f"{t:>12}" for t in results["tools"])
    print(header)
    print("-" * len(header))
    for v in VARIANTS:
        row = f"{v:<24}"
        for t in results["tools"]:
            row += f"{results['tools'][t]['by_variant'][v]['rate']:>11.1%} "
        print(row)
    print()
    for t, a in results["tools"].items():
        o = a["overall"]
        print(f"{t}: precision={o['precision']:.3f} recall={o['recall']:.3f} "
              f"F1={o['f1']:.3f} FPR={o['fpr']:.3f} TP={o['tp']} FP={o['fp']}")


if __name__ == "__main__":
    main()
