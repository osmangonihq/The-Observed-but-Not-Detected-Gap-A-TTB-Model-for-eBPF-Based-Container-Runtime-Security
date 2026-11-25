"""Trust-boundary checks.

Each check looks for a *trust anchor*: a sub-expression of a detection rule
whose truth value is not guaranteed by the kernel observation itself.  Anchors
are reported with the literal evidence from the policy so that every finding is
independently verifiable against the upstream source.
"""

from __future__ import annotations

import re
from typing import Callable

from .model import Finding, Rule, TrustClass

Check = Callable[[Rule], list[Finding]]


def _evidence(rule: Rule, pattern: str, limit: int = 4) -> str:
    matches = re.findall(pattern, rule.raw, re.IGNORECASE)
    if isinstance(matches[0] if matches else "", tuple):
        matches = [m[0] if isinstance(m, tuple) else str(m) for m in matches]
    unique = list(dict.fromkeys(str(m).strip() for m in matches))
    shown = "; ".join(unique[:limit])
    if len(unique) > limit:
        shown += f" (+{len(unique) - limit} more)"
    return shown or "(pattern present)"


def _finding(
    rule: Rule,
    check_id: str,
    tc: TrustClass,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        trust_class=tc,
        severity=severity,
        title=title,
        evidence=evidence,
        recommendation=recommendation,
        rule_id=rule.id,
        tool=rule.tool,
        source_file=rule.source_file,
    )


# --- TB-01: privilege attribute trust --------------------------------------
TB01_PATTERN = (
    r"container\.privileged\s*=\s*true|privileged:\s*true|"
    r"thread\.cap_effective|cap_effective|CAP_SYS_ADMIN|CAP_BPF|CAP_SYS_PTRACE|"
    r"user\.uid\s*=\s*0|uid=0|matchCapabilities|effectiveCaps"
)


def tb01_privilege_attribute(rule: Rule) -> list[Finding]:
    if not re.search(TB01_PATTERN, rule.raw, re.IGNORECASE):
        return []
    return [_finding(
        rule, "TB-01", TrustClass.PRIVILEGE_ATTRIBUTE, "critical",
        "Detection conditioned on launch-time privilege metadata",
        _evidence(rule, TB01_PATTERN),
        "Re-validate privilege at event time with credential/capability-change "
        "hooks (setuid, capset, commit_creds) instead of trusting container "
        "runtime metadata or exec-time snapshots.",
    )]


# --- TB-02: identity / allowlist trust -------------------------------------
TB02_PATTERN = (
    r"trusted_images|falco_privileged_images|k8s_containers|"
    r"container\.image\.repository\s+in|containerImage=|"
    r"user_known_[A-Za-z0-9_]+|allowed_[A-Za-z0-9_]+|"
    r"not\s+[^\n]{0,60}\s+in\s*\(|never_true|kube-system|"
    r"matchBinaries|matchNamespaces"
)


def tb02_identity_allowlist(rule: Rule) -> list[Finding]:
    if not re.search(TB02_PATTERN, rule.raw, re.IGNORECASE):
        return []
    sev = "high"
    if re.search(r"never_true|user_known_|allowed_", rule.raw, re.IGNORECASE):
        sev = "medium"   # empty-by-default but unbounded when tuned
    return [_finding(
        rule, "TB-02", TrustClass.IDENTITY_ALLOWLIST, sev,
        "Suppression delegated to mutable identity allowlists",
        _evidence(rule, TB02_PATTERN),
        "Constrain allowlists to immutable workload identity (signed image "
        "digest + namespace + service account), forbid wildcards, and require "
        "a second signal before suppressing an escape-relevant event.",
    )]


# --- TB-03: telemetry state trust ------------------------------------------
TB03_PATTERN = (
    r"not\s+proc\.pname\s+exists|proc_name_exists|not\s+proc\.name\s+exists|"
    r"N/A|<NA>|evt\.num\s*=\s*0|container=new|container=started|"
    r"containerStarted|container!=started|not-container|"
    r"not\s+proc\.name\s+in\s*\(\s*[\"']?N/A"
)


def tb03_telemetry_state(rule: Rule) -> list[Finding]:
    if not re.search(TB03_PATTERN, rule.raw, re.IGNORECASE):
        return []
    return [_finding(
        rule, "TB-03", TrustClass.TELEMETRY_STATE, "high",
        "Missing or inferred telemetry treated as a decision input",
        _evidence(rule, TB03_PATTERN),
        "Fail closed: an absent process/parent field must not be interpreted as "
        "'trusted entrypoint'. Recover identity from kernel-resolved fields "
        "(exepath, cgroup id, namespace inode) and alert on telemetry gaps.",
    )]


# --- TB-04: signature-name narrowness --------------------------------------
TB04_PATTERN = (
    r"proc\.name\s*=|proc\.pname\s*=|proc\.exe\s*=|proc\.exepath\s*=|"
    r"matchBinaries|comm=|processName=|executable=|"
    r"proc\.name\s+in\s*\([^)]*\)"
)


def tb04_signature_name(rule: Rule) -> list[Finding]:
    if not re.search(TB04_PATTERN, rule.raw, re.IGNORECASE):
        return []
    return [_finding(
        rule, "TB-04", TrustClass.SIGNATURE_NAME, "high",
        "Detection keyed on a tool or binary name",
        _evidence(rule, TB04_PATTERN, limit=3),
        "Express the rule over the invariant syscall/kernel-object behavior "
        "(write to release_agent, setns into host ns), not the utility name; "
        "keep names only as a low-weight enrichment signal.",
    )]


# --- TB-05: missing cross-layer correlation --------------------------------
def tb05_cross_layer(rule: Rule) -> list[Finding]:
    md = rule.metadata
    has_lsm_hook = md.get("has_lsm_hook", "").lower() == "true"
    has_kprobe = md.get("has_kprobe", "").lower() == "true"
    hook_group = md.get("hook_group", "")
    raw_lsm = re.search(
        r"bprm_check_security|security_file_open|security_sb_mount|"
        r"security_bprm_check|lsmhooks|security_[a-z_]+",
        rule.raw, re.IGNORECASE,
    )

    syscall_visible = bool(
        re.search(
            r"evt\.type|spawned_process|init_module|openat|\bmount\b|"
            r"\bptrace\b|execve|setuid|\bopen_write\b|sched_process_exec|"
            r"\bopen\b|\bcall\b",
            rule.raw, re.IGNORECASE,
        )
    )
    if not syscall_visible:
        return []
    # LSM hooks read arguments at security-check time and are therefore not
    # exposed to the userspace argument TOCTOU documented by both vendors.
    if hook_group == "lsmhooks" or (has_lsm_hook and not has_kprobe):
        return []
    if raw_lsm and not has_kprobe:
        return []
    # Exec and file-write decisions are the most TOCTOU-sensitive.
    severity = (
        "high"
        if rule.observables & {"exec", "file-write", "open-file", "host-config-write"}
        else "medium"
    )
    return [_finding(
        rule, "TB-05", TrustClass.CROSS_LAYER, severity,
        "Single-layer syscall observation without LSM cross-check",
        f"hook_group={hook_group or 'n/a'}; has_lsm_hook={has_lsm_hook}; "
        f"has_kprobe={has_kprobe}; syscall-level pattern present",
        "Correlate the syscall event with its LSM counterpart "
        "(security_bprm_check, security_file_open, security_sb_mount) so that "
        "argument TOCTOU and post-check credential changes are visible.",
    )]


# --- TB-06: temporal / snapshot scope --------------------------------------
TB06_PATTERN = (
    r"container=new|container=started|proc_is_new|proc\.duration|"
    r"container_start_ts|proc\.exe_ino\.ctime_duration_proc_start|"
    r"thread\.cap_effective|threat\.severity\s*=|threat\.mitre\.|"
    r"detector selection|at process creation|exec time"
)


def tb06_temporal_scope(rule: Rule) -> list[Finding]:
    if not re.search(TB06_PATTERN, rule.raw, re.IGNORECASE):
        return []
    return [_finding(
        rule, "TB-06", TrustClass.TEMPORAL_SCOPE, "medium",
        "Decision bound to a single time snapshot or startup state",
        _evidence(rule, TB06_PATTERN, limit=3),
        "Treat identity and privilege as a time series: re-evaluate at each "
        "security-relevant hook, and avoid scoping detections to container "
        "startup phases or to a detector set fixed at agent start.",
    )]


CHECKS: tuple[Check, ...] = (
    tb01_privilege_attribute,
    tb02_identity_allowlist,
    tb03_telemetry_state,
    tb04_signature_name,
    tb05_cross_layer,
    tb06_temporal_scope,
)
