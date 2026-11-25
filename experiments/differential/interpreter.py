"""Abstract policy interpreter for the differential experiment.

This is deliberately NOT a reimplementation of the Falco/Tetragon/Tracee
engines. It consumes the trust anchors that the auditor extracted from each
real rule and asks a single question: given an event whose metadata has been
modified in one specific way, does any rule whose observable matches still
evaluate to true?  The result isolates the logical consequence of the trust
anchors themselves.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "auditor"))
from typing import Iterable

from ttb_auditor.engine import audit_directory
from ttb_auditor.model import Observable

from events import SecEvent


SIGNATURE_PATTERNS: dict[str, str] = {
    "release_agent": "release_agent",
    "core_pattern": "core_pattern",
    "modprobe": "modprobe",
    "memfd": "memfd",
    "fileless": "memfd",
    "ptrace": "ptrace",
    "code_injection": "ptrace",
    "mount": "mount",
    "disk_mount": "mount",
    "cgroup": "cgroup",
    "kernel_module": "module",
    "docker_abuse": "docker",
    "k8s_api": "kubernetes",
    "setuid": "setuid",
    "capset": "capset",
    "environ": "environ",
    "bpf": "bpf",
}


def _signature_pattern(name: str) -> str | None:
    lowered = name.lower()
    for key, pattern in SIGNATURE_PATTERNS.items():
        if key in lowered:
            return pattern
    return None


@dataclass
class AbstractRule:
    tool: str
    name: str
    source_file: str
    observables: frozenset[Observable]
    anchors: frozenset[str]
    kind: str                      # "condition" or "signature"
    semantic_pattern: str | None   # target encoded in a detector/event name

    @classmethod
    def from_audit(cls, rule_audit) -> "AbstractRule":
        r = rule_audit.rule
        # Tracee event names and Tetragon LSM hooks with actions are
        # signature-style: the detector name itself encodes a semantic check.
        is_signature = (
            r.tool == "Tracee"
            or (r.tool == "Tetragon" and r.metadata.get("hook_group") == "lsmhooks")
        )
        return cls(
            tool=r.tool,
            name=r.name,
            source_file=r.source_file,
            observables=frozenset(r.observables),
            anchors=frozenset(f.check_id for f in rule_audit.findings),
            kind="signature" if is_signature else "condition",
            # Both signature detectors and path-scoped conditions encode a
            # target in their name/condition text; require it for the benign
            # look-alike to be separated from the malicious event.
            semantic_pattern=_signature_pattern(r.name + " " + r.raw[:500]),
        )


def anchor_ok(check_id: str, event: SecEvent) -> bool:
    """Evaluate one trust anchor against the event's metadata state."""
    if check_id == "TB-01":
        return event.cap_ok or event.privileged_launch
    if check_id == "TB-02":
        return event.identity_ok
    if check_id == "TB-03":
        return event.parent_ok
    if check_id == "TB-04":
        return event.name_ok
    if check_id == "TB-05":
        return event.cross_layer_ok
    if check_id == "TB-06":
        return event.snapshot_ok
    return True


def semantic_ok(rule: AbstractRule, event: SecEvent) -> bool:
    """Signature detectors must match the target encoded in their name."""
    if rule.kind != "signature" or not rule.semantic_pattern:
        return True
    pattern = rule.semantic_pattern
    if pattern in event.syscall_path.lower():
        return True
    # Some detectors match on an event class rather than a literal path.
    class_map = {
        "memfd": "memfd-exec", "ptrace": "ptrace", "mount": "mount",
        "module": "module-load", "bpf": "bpf-load", "setuid": "credential-change",
        "capset": "credential-change", "docker": "unix-socket",
        "kubernetes": "unix-socket", "cgroup": "host-config-write",
        "environ": "credential-read",
    }
    return class_map.get(pattern) == event.observable.value


def fires(rule: AbstractRule, event: SecEvent) -> bool:
    if not (rule.observables & {event.observable}):
        return False
    if not semantic_ok(rule, event):
        return False
    return all(anchor_ok(a, event) for a in rule.anchors)


def load_rules(policies_dir: Path) -> dict[str, list[AbstractRule]]:
    audits = audit_directory(policies_dir)
    return {
        tool: [AbstractRule.from_audit(ra) for ra in audit.rule_audits]
        for tool, audit in audits.items()
    }


def detect(tool_rules: Iterable[AbstractRule], event: SecEvent) -> list[str]:
    """Return the names of every rule that fires for this event."""
    return [r.name for r in tool_rules if fires(r, event)]
