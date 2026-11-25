"""Core data model for the Telemetry-Trust Boundary auditor.

The model encodes the paper's central distinction:

    detection = observation AND policy_decision

An event can be fully observed by an eBPF sensor yet fail to produce an alert
because the policy decision delegates to a *trust anchor* whose value is not
guaranteed by the observation mechanism.  The classes of trust anchors are
enumerated in :class:`TrustClass`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class TrustClass(str, Enum):
    """Classes of trust anchors that can break observation -> detection."""

    PRIVILEGE_ATTRIBUTE = "privilege-attribute"   # workload-declared privilege metadata
    IDENTITY_ALLOWLIST = "identity-allowlist"     # trusted image / namespace / binary lists
    TELEMETRY_STATE = "telemetry-state"           # missing / inferred telemetry fields
    SIGNATURE_NAME = "signature-name"             # exact binary/path/tool names
    CROSS_LAYER = "cross-layer"                   # absent LSM/second-hook correlation
    TEMPORAL_SCOPE = "temporal-scope"             # exec-time snapshots, container state


# Weights used by the Trust Dependency Score (TDS).  They reflect the relative
# ease with which a privileged in-container adversary can invalidate the anchor.
TRUST_WEIGHTS: dict[TrustClass, float] = {
    TrustClass.PRIVILEGE_ATTRIBUTE: 0.22,
    TrustClass.IDENTITY_ALLOWLIST: 0.18,
    TrustClass.TELEMETRY_STATE: 0.18,
    TrustClass.SIGNATURE_NAME: 0.16,
    TrustClass.CROSS_LAYER: 0.16,
    TrustClass.TEMPORAL_SCOPE: 0.10,
}


# Generic observable vocabulary.  Tool parsers map vendor-specific field names
# onto these tokens so that a technique can be matched across all three tools.
class Observable(str, Enum):
    OPEN_FILE = "open-file"                         # open/openat of a path
    FILE_READ = "file-read"                         # read of a host-sensitive path
    DEVICE_ACCESS = "device-access"                 # /dev/mem, /dev/kmem, raw devices
    MEMORY_FAULT = "memory-fault"                   # userfaultfd-style memory manipulation
    IO_URING = "io-uring"                           # io_uring setup / exploit surface
    CREDENTIAL_READ = "credential-read"             # reading host credential material
    FILE_WRITE = "file-write"                       # write to an arbitrary path
    HOST_CONFIG_WRITE = "host-config-write"         # write to cgroup/proc/sys host config
    MOUNT = "mount"                                 # mount(2), pivot_root
    NAMESPACE_ENTRY = "namespace-entry"             # setns, /proc/<pid>/ns access
    PTRACE = "ptrace"                               # ptrace, process_vm_writev
    BPF_LOAD = "bpf-load"                           # bpf(2), perf_event_open
    CREDENTIAL_CHANGE = "credential-change"         # setuid/capset/commit_creds
    EXEC = "exec"                                   # execve / bprm_check
    MEMFD_EXEC = "memfd-exec"                       # memfd_create + execveat
    UNIX_SOCKET = "unix-socket"                     # /var/run/docker.sock connect
    MODULE_LOAD = "module-load"                     # init_module / finit_module
    PIPE_SPLICE = "pipe-splice"                     # Dirty Pipe style write
    SIGNAL = "signal"                               # kill/tgkill (host process)
    DUP_REDIRECT = "dup-redirect"                   # stdout/stdin -> socket


@dataclass(frozen=True)
class Technique:
    """A container-escape primitive with its observable surface."""

    id: str
    name: str
    mitre: str
    required_privilege: str
    observables: frozenset[Observable]
    name_dependent: bool
    description: str
    variants: tuple[str, ...] = ()
    cve: str | None = None


@dataclass
class Rule:
    """A normalized detection rule from any of the three tools."""

    id: str
    tool: str
    source_file: str
    name: str
    raw: str
    observables: set[Observable] = field(default_factory=set)
    signals: set[str] = field(default_factory=set)
    enabled: bool = True
    metadata: dict[str, str] = field(default_factory=dict)

    def add(self, *observables: Observable) -> None:
        self.observables.update(observables)


@dataclass
class Finding:
    """One trust-boundary defect found in a rule."""

    check_id: str
    trust_class: TrustClass
    severity: str          # critical | high | medium | low
    title: str
    evidence: str
    recommendation: str
    rule_id: str = ""
    tool: str = ""
    source_file: str = ""

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "trust_class": self.trust_class.value,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "rule_id": self.rule_id,
            "tool": self.tool,
            "source_file": self.source_file,
        }


@dataclass
class RuleAudit:
    rule: Rule
    findings: list[Finding] = field(default_factory=list)

    @property
    def tds(self) -> float:
        """Trust Dependency Score in [0, 1].

        Class weights are scaled by severity so that a configurable-but-empty
        allowlist (medium) is not treated as equivalent to an active reliance
        on stale privilege metadata (critical).
        """
        factor = {"critical": 1.0, "high": 1.0, "medium": 0.4, "low": 0.2}
        return min(
            1.0,
            sum(TRUST_WEIGHTS[f.trust_class] * factor.get(f.severity, 0.4)
                for f in self.findings),
        )

    @property
    def robust(self) -> bool:
        """A rule is robust iff no high/critical defect and low aggregate trust."""
        if any(f.severity in ("critical", "high") for f in self.findings):
            return False
        return self.tds < 0.25

    @property
    def trust_classes(self) -> set[TrustClass]:
        return {f.trust_class for f in self.findings}


@dataclass
class TechniqueVerdict:
    technique: Technique
    covering_rules: list[RuleAudit] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return bool(self.covering_rules)

    @property
    def robust_detection(self) -> bool:
        return any(r.robust for r in self.covering_rules)

    @property
    def classification(self) -> str:
        if not self.covered:
            return "no-rule"
        if self.robust_detection:
            return "detected"
        return "observed-not-detected"  # <-- the gap this paper formalizes

    @property
    def best_tds(self) -> float | None:
        if not self.covering_rules:
            return None
        return min(r.tds for r in self.covering_rules)


@dataclass
class ToolAudit:
    tool: str
    source_files: list[str]
    rule_audits: list[RuleAudit]
    verdicts: list[TechniqueVerdict]

    @property
    def findings(self) -> list[Finding]:
        return [f for ra in self.rule_audits for f in ra.findings]

    @property
    def mean_tds(self) -> float:
        if not self.rule_audits:
            return 0.0
        return sum(ra.tds for ra in self.rule_audits) / len(self.rule_audits)

    @property
    def gap_count(self) -> int:
        return sum(v.classification == "observed-not-detected" for v in self.verdicts)

    @property
    def detected_count(self) -> int:
        return sum(v.classification == "detected" for v in self.verdicts)

    @property
    def uncovered_count(self) -> int:
        return sum(v.classification == "no-rule" for v in self.verdicts)

    @property
    def gap_ratio(self) -> float:
        denom = self.gap_count + self.detected_count
        return self.gap_count / denom if denom else 0.0

    def class_counts(self, classes: Iterable[TrustClass]) -> dict[str, int]:
        wanted = set(classes)
        return {
            c.value: sum(1 for f in self.findings if f.trust_class == c)
            for c in wanted
        }
