"""Regression tests for the TTB auditor's parsers, checks and scoring."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ttb_auditor.checks import CHECKS  # noqa: E402
from ttb_auditor.corpus import TECHNIQUES, corpus_summary  # noqa: E402
from ttb_auditor.engine import audit_directory  # noqa: E402
from ttb_auditor.model import (  # noqa: E402
    Finding,
    Observable,
    Rule,
    RuleAudit,
    Technique,
    TechniqueVerdict,
    TrustClass,
)
from ttb_auditor.parsers import parse_file  # noqa: E402

POLICIES = ROOT.parent / "experiments" / "policies"


def find_policy(tool: str, needle: str) -> Path:
    """Find a policy file by substring, regardless of corpus dedup layout."""
    for path in sorted((POLICIES / tool).rglob("*.y*ml")):
        if needle in path.name:
            return path
    raise FileNotFoundError(f"{needle} under {tool}")


class TestCorpus(unittest.TestCase):
    def test_corpus_nonempty_and_unique(self):
        ids = [t.id for t in TECHNIQUES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(TECHNIQUES), 12)
        self.assertEqual(corpus_summary()["techniques"], len(TECHNIQUES))

    def test_every_technique_has_observables(self):
        for t in TECHNIQUES:
            self.assertTrue(t.observables, t.id)


class TestParsers(unittest.TestCase):
    def test_falco_ruleset(self):
        tool, rules = parse_file(find_policy("falco", "falco_rules"))
        self.assertEqual(tool, "Falco")
        self.assertGreater(len(rules), 20)
        names = {r.name for r in rules}
        self.assertIn("Detect release_agent File Container Escapes", names)
        release = next(r for r in rules if r.name.startswith("Detect release_agent"))
        self.assertIn(Observable.HOST_CONFIG_WRITE, release.observables)

    def test_tetragon_policy(self):
        tool, rules = parse_file(find_policy("tetragon", "lsm_bprm_check"))
        self.assertEqual(tool, "Tetragon")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].metadata["hook_group"], "lsmhooks")
        self.assertIn(Observable.EXEC, rules[0].observables)

    def test_tracee_policy(self):
        tool, rules = parse_file(find_policy("tracee", "signature_events"))
        self.assertEqual(tool, "Tracee")
        self.assertGreater(len(rules), 20)
        names = {r.name for r in rules}
        self.assertTrue(any("cgroup_release_agent" in n for n in names))


class TestChecks(unittest.TestCase):
    def _audit(self, rule: Rule) -> RuleAudit:
        findings = [f for check in CHECKS for f in check(rule)]
        return RuleAudit(rule=rule, findings=findings)

    def test_privilege_anchor_is_critical(self):
        r = Rule("r", "Falco", "f", "escape", "container.privileged=true and open_write",
                 observables={Observable.FILE_WRITE})
        a = self._audit(r)
        self.assertTrue(any(f.check_id == "TB-01" and f.severity == "critical" for f in a.findings))
        self.assertFalse(a.robust)

    def test_lsm_hook_exempt_from_toctou_check(self):
        r = Rule("r", "Tetragon", "f", "lsm", "bprm_check_security execve",
                 observables={Observable.EXEC},
                 metadata={"hook_group": "lsmhooks", "has_lsm_hook": "True", "has_kprobe": "False"})
        a = self._audit(r)
        self.assertFalse(any(f.check_id == "TB-05" for f in a.findings))

    def test_syscall_exec_not_robust(self):
        r = Rule("r", "Falco", "f", "exec", "spawned_process and shell_procs",
                 observables={Observable.EXEC})
        a = self._audit(r)
        self.assertTrue(any(f.check_id == "TB-05" and f.severity == "high" for f in a.findings))
        self.assertFalse(a.robust)

    def test_ts_never_robust_when_high_finding(self):
        r = Rule("r", "T", "f", "n", "x")
        a = RuleAudit(r, [Finding("TB-01", TrustClass.PRIVILEGE_ATTRIBUTE, "critical", "t", "e", "r")])
        self.assertFalse(a.robust)
        self.assertAlmostEqual(a.tds, 0.22)

    def test_empty_findings_are_robust(self):
        r = Rule("r", "T", "f", "n", "x")
        a = RuleAudit(r)
        self.assertTrue(a.robust)
        self.assertEqual(a.tds, 0.0)


class TestVerdict(unittest.TestCase):
    def _tech(self, obs):
        return Technique("X", "x", "T", "none", frozenset({obs}), False, "d")

    def test_classification(self):
        tech = self._tech(Observable.MODULE_LOAD)
        good = Rule("g", "T", "f", "good", "x", observables={Observable.MODULE_LOAD})
        bad = Rule("b", "T", "f", "bad", "container.privileged=true",
                   observables={Observable.MODULE_LOAD})
        self.assertEqual(TechniqueVerdict(tech, [RuleAudit(good)]).classification, "detected")
        ga = RuleAudit(good)
        ba = RuleAudit(bad, [Finding("TB-01", TrustClass.PRIVILEGE_ATTRIBUTE,
                                     "critical", "t", "e", "r")])
        self.assertEqual(TechniqueVerdict(tech, [ba]).classification, "observed-not-detected")
        self.assertEqual(TechniqueVerdict(tech, [ga, ba]).classification, "detected")
        self.assertEqual(TechniqueVerdict(tech, []).classification, "no-rule")


class TestEndToEnd(unittest.TestCase):
    def test_audit_directory(self):
        results = audit_directory(POLICIES)
        self.assertEqual(set(results), {"Falco", "Tetragon", "Tracee"})
        for tool, audit in results.items():
            self.assertGreater(audit.rule_count if hasattr(audit, "rule_count") else len(audit.rule_audits), 0)
            self.assertEqual(len(audit.verdicts), len(TECHNIQUES))
            self.assertGreaterEqual(audit.gap_ratio, 0.0)
            self.assertLessEqual(audit.gap_ratio, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
