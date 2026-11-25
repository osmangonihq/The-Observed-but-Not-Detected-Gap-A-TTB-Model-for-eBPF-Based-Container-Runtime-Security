"""Vendor-specific policy parsers that normalize into :class:`Rule`.

Supported inputs
----------------
* Falco rules YAML (``falcosecurity/rules``).
* Tetragon ``TracingPolicy`` custom resources.
* Tracee ``Policy`` custom resources (CRD and plain formats).

The parsers deliberately keep the *raw* policy text on each rule: every finding
reported by the auditor is traceable back to a literal fragment of the source
policy, which is essential for a reviewer to verify the audit.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .model import Observable, Rule

# ---------------------------------------------------------------------------
# Signal vocabularies: vendor token -> generic observable(s)
# ---------------------------------------------------------------------------

FALCO_SIGNALS: list[tuple[str, tuple[Observable, ...]]] = [
    (r"\b(?:init_module|finit_module|kernel_module_load)\b", (Observable.MODULE_LOAD,)),
    (r"release_agent", (Observable.HOST_CONFIG_WRITE,)),
    (r"core_pattern", (Observable.HOST_CONFIG_WRITE,)),
    (r"modprobe", (Observable.HOST_CONFIG_WRITE,)),
    (r"\bdebugfs\b", (Observable.MOUNT,)),
    (r"\bmount\b", (Observable.MOUNT,)),
    (r"\bsetns\b", (Observable.NAMESPACE_ENTRY,)),
    (r"\bchroot\b|\bpivot_root\b", (Observable.NAMESPACE_ENTRY, Observable.MOUNT)),
    (r"\bptrace\b", (Observable.PTRACE,)),
    (r"process_vm_write", (Observable.PTRACE,)),
    (r"memfd_create|is_exe_from_memfd", (Observable.MEMFD_EXEC,)),
    (r"\bbpf\b", (Observable.BPF_LOAD,)),
    (r"open_write|open_read|evt\.type in \(open,openat,openat2\)", (Observable.OPEN_FILE, Observable.FILE_WRITE)),
    (r"AF_UNIX|/var/run/docker\.sock|unix_socket", (Observable.UNIX_SOCKET,)),
    (r"cap_effective|user\.uid|setuid|setgid", (Observable.CREDENTIAL_CHANGE,)),
    (r"\bdup\b", (Observable.DUP_REDIRECT,)),
    (r"spawned_process|evt\.type in \(execve,execveat\)", (Observable.EXEC,)),
    (r"open_by_handle_at|name_to_handle_at", (Observable.OPEN_FILE, Observable.FILE_READ)),
    (r"/dev/mem|/dev/kmem|CAP_SYS_RAWIO", (Observable.DEVICE_ACCESS, Observable.FILE_READ)),
    (r"userfaultfd", (Observable.MEMORY_FAULT,)),
    (r"io_uring", (Observable.IO_URING,)),
    (r"/proc/[^\s\"']*/environ|proc\.cmdline.*environ", (Observable.CREDENTIAL_READ,)),
    (r"authorized_keys|ld\.so\.preload|crontab|systemd.*unit", (Observable.HOST_CONFIG_WRITE,)),
]

TETRAGON_SIGNALS: list[tuple[str, tuple[Observable, ...]]] = [
    (r"['\"]?mount['\"]?|pivot_root|chroot", (Observable.MOUNT,)),
    (r"setns|fd_install.*matchNamespaces|namespace:\s*(?:Pid|Mount|Mnt)", (Observable.NAMESPACE_ENTRY,)),
    (r"ptrace|process_vm_writev", (Observable.PTRACE,)),
    (r"\bbpf\b|bpf_check|bpf_map|perf_event_open", (Observable.BPF_LOAD,)),
    (r"setuid|setgid|capset|commit_creds|cap_capset", (Observable.CREDENTIAL_CHANGE,)),
    (r"execve|execveat|sched_process_exec|bprm_check_security", (Observable.EXEC,)),
    (r"\bopenat2?\b|filename_monitoring|file_open", (Observable.OPEN_FILE, Observable.FILE_WRITE)),
    (r"init_module|finit_module", (Observable.MODULE_LOAD,)),
    (r"memfd_create", (Observable.MEMFD_EXEC,)),
    (r"unix_connect|AF_UNIX|/var/run/docker\.sock", (Observable.UNIX_SOCKET,)),
    (r"\bpipe\b|\bsplice\b|vmsplice", (Observable.PIPE_SPLICE,)),
    (r"open_by_handle_at|name_to_handle_at", (Observable.OPEN_FILE, Observable.FILE_READ)),
    (r"/dev/mem|/dev/kmem", (Observable.DEVICE_ACCESS, Observable.FILE_READ)),
    (r"userfaultfd", (Observable.MEMORY_FAULT,)),
    (r"io_uring", (Observable.IO_URING,)),
    (r"environ", (Observable.CREDENTIAL_READ,)),
]

TRACEE_SIGNALS: list[tuple[str, tuple[Observable, ...]]] = [
    (r"cgroup_release_agent|cgroup_notify_on_release", (Observable.HOST_CONFIG_WRITE,)),
    (r"core_pattern_modification|default_loader_mod", (Observable.HOST_CONFIG_WRITE,)),
    (r"kernel_module_loading", (Observable.MODULE_LOAD,)),
    (r"ptrace_code_injection|process_vm_write_inject|process_injection", (Observable.PTRACE,)),
    (r"fileless_execution", (Observable.MEMFD_EXEC,)),
    (r"disk_mount", (Observable.MOUNT,)),
    (r"security_file_open", (Observable.OPEN_FILE, Observable.FILE_WRITE)),
    (r"data\.pathname=/(?:sys|proc)", (Observable.HOST_CONFIG_WRITE,)),
    (r"sched_process_exec|security_bprm_check", (Observable.EXEC,)),
    (r"\bsetuid\b|\bcapset\b", (Observable.CREDENTIAL_CHANGE,)),
    (r"docker_abuse|k8s_api_connection", (Observable.UNIX_SOCKET,)),
    (r"stdio_over_socket", (Observable.DUP_REDIRECT,)),
    (r"open_by_handle_at", (Observable.OPEN_FILE, Observable.FILE_READ)),
    (r"proc_mem_access|proc_kcore_read", (Observable.DEVICE_ACCESS, Observable.FILE_READ)),
    (r"userfaultfd", (Observable.MEMORY_FAULT,)),
    (r"io_uring", (Observable.IO_URING,)),
    (r"env_val|environment", (Observable.CREDENTIAL_READ,)),
]


def _signals_from(text: str, table: list[tuple[str, tuple[Observable, ...]]]) -> tuple[set[Observable], set[str]]:
    obs: set[Observable] = set()
    hits: set[str] = set()
    for pattern, mapped in table:
        if re.search(pattern, text, re.IGNORECASE):
            obs.update(mapped)
            hits.add(pattern)
    return obs, hits


def _expand_falco_macros(items: list[dict[str, Any]]):
    macro_map: dict[str, str] = {}
    for item in items:
        if isinstance(item, dict) and "macro" in item:
            macro_map[str(item["macro"])] = str(item.get("condition", ""))

    def expand(text: str, seen: frozenset[str] = frozenset()) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in seen or name not in macro_map:
                return match.group(0)
            return " ( " + expand(macro_map[name], seen | {name}) + " ) "
        return re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\b(?=\s|\(|$)", repl, text)

    return macro_map, expand


def _flatten(value: Any) -> str:
    """Flatten a parsed YAML fragment into a searchable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    if isinstance(value, dict):
        return " ".join(f"{k} {_flatten(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def parse_falco(path: Path) -> list[Rule]:
    items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    macro_map, expand = _expand_falco_macros(items)
    rules: list[Rule] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict) or "rule" not in item:
            continue
        raw_condition = str(item.get("condition", ""))
        expanded = expand(raw_condition)
        obs, hits = _signals_from(expanded + " " + raw_condition, FALCO_SIGNALS)
        # Macro *names* themselves can be signature anchors (e.g. debugfs).
        name_hits, name_obs = _signals_from(
            " ".join(re.findall(r"\b([a-z_]+(?:_macro|_binary|_binaries))\b", expanded)), FALCO_SIGNALS
        )
        obs.update(name_obs)
        hits.update(name_hits)
        rule = Rule(
            id=f"falco:{path.name}:{idx}:{item['rule']}",
            tool="Falco",
            source_file=str(path),
            name=str(item["rule"]),
            raw=raw_condition,
            observables=obs,
            signals=hits,
            enabled=bool(item.get("enabled", True)),
            metadata={
                "description": str(item.get("desc", ""))[:600],
                "priority": str(item.get("priority", "")),
                "tags": ",".join(item.get("tags", []) or []),
                "macro_count": str(len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", raw_condition))),
            },
        )
        rules.append(rule)
    return rules


def parse_tetragon(path: Path) -> list[Rule]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict) or "spec" not in doc:
        return []
    spec = doc.get("spec", {}) or {}
    raw = _flatten(spec)
    obs, hits = _signals_from(raw, TETRAGON_SIGNALS)
    name = str((doc.get("metadata") or {}).get("name", path.stem))
    # Each hook is reported as a rule so that the audit can point to a
    # specific kprobe/LSM hook as the trust-bearing decision point.
    rules: list[Rule] = []
    hook_groups = [
        ("kprobes", spec.get("kprobes") or []),
        ("tracepoints", spec.get("tracepoints") or []),
        ("lsmhooks", spec.get("lsmhooks") or []),
        ("uprobes", spec.get("uprobes") or []),
    ]
    for group, hooks in hook_groups:
        for idx, hook in enumerate(hooks):
            hraw = _flatten(hook)
            hobbs, hhits = _signals_from(hraw, TETRAGON_SIGNALS)
            rules.append(
                Rule(
                    id=f"tetragon:{path.name}:{group}:{idx}",
                    tool="Tetragon",
                    source_file=str(path),
                    name=f"{name}/{group}[{idx}]:{hook.get('call') or hook.get('hook') or hook.get('event') or 'hook'}",
                    raw=hraw,
                    observables=hobbs or obs,
                    signals=hhits or hits,
                    metadata={
                        "hook_group": group,
                        "has_lsm_hook": str(bool(spec.get("lsmhooks"))),
                        "has_kprobe": str(bool(spec.get("kprobes"))),
                        "selector_count": str(len(hook.get("selectors") or [])),
                    },
                )
            )
    return rules


def parse_tracee(path: Path) -> list[Rule]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        return []
    spec = doc.get("spec", doc)
    if not isinstance(spec, dict) or "rules" not in spec:
        return []
    scope = " ".join(str(s) for s in (spec.get("scope") or []))
    name = str((doc.get("metadata") or {}).get("name", doc.get("name", path.stem)))
    rules: list[Rule] = []
    for idx, entry in enumerate(spec.get("rules", [])):
        raw = _flatten(entry)
        obs, hits = _signals_from(" ".join([str(entry.get("event", "")), raw]), TRACEE_SIGNALS)
        rules.append(
            Rule(
                id=f"tracee:{path.name}:{idx}:{entry.get('event', 'event')}",
                tool="Tracee",
                source_file=str(path),
                name=f"{name}/{entry.get('event', 'event')}",
                raw=f"scope: {scope} | {raw}",
                observables=obs,
                signals=hits,
                metadata={
                    "scope": scope,
                    "event": str(entry.get("event", "")),
                    "filters": _flatten(entry.get("filters") or []),
                },
            )
        )
    return rules


def parse_file(path: Path) -> tuple[str, list[Rule]]:
    """Detect the tool from file content and parse accordingly."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if "kind: TracingPolicy" in text:
        return "Tetragon", parse_tetragon(path)
    if "kind: Policy" in text or "type: policy" in text:
        return "Tracee", parse_tracee(path)
    if re.search(r"^\s*-\s*rule\s*:", text, re.MULTILINE):
        return "Falco", parse_falco(path)
    return "unknown", []
