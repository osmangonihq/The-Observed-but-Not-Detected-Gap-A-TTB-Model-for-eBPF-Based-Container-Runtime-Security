"""Synthetic event generation for the differential experiment.

Every event is modeled on a documented syscall signature; no exploit code is
used. For each escape primitive we emit a malicious baseline, seven variants
that invalidate one trust anchor each, and one benign look-alike that shares
the same observable surface but occurs in a legitimate context.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "auditor"))

from ttb_auditor.corpus import TECHNIQUES
from ttb_auditor.model import Observable

if TYPE_CHECKING:
    from ttb_auditor.model import Technique

SYS_ADMIN = "CAP_SYS_ADMIN"

# technique id -> (expected tool name, representative syscall path, capability)
META: dict[str, tuple[str | None, str, set[str]]] = {
    "T01": (None, "/sys/fs/cgroup/rdma/release_agent", {SYS_ADMIN}),
    "T02": (None, "/proc/sys/kernel/core_pattern", {SYS_ADMIN}),
    "T03": (None, "/proc/sys/kernel/modprobe", {SYS_ADMIN}),
    "T04": ("debugfs", "/sys/kernel/debug", {SYS_ADMIN}),
    "T05": ("nsenter", "/proc/1/ns/mnt", {SYS_ADMIN}),
    "T06": (None, "/proc/1/root", {SYS_ADMIN}),
    "T07": ("docker", "/var/run/docker.sock", set()),
    "T08": (None, "/etc/passwd", set()),
    "T09": (None, "setuid(0)", set()),
    "T10": (None, "/bin/ls", set()),
    "T11": ("insmod", "/lib/modules/payload.ko", {"CAP_SYS_MODULE"}),
    "T12": ("bpftool", "bpf(BPF_PROG_LOAD)", {"CAP_BPF"}),
    "T13": ("gdb", "ptrace(PTRACE_POKETEXT)", {"CAP_SYS_PTRACE"}),
    "T14": (None, "memfd:payload", set()),
    "T15": ("mount", "/proc/1/root", {SYS_ADMIN}),
    "T16": (None, "open_by_handle_at()", {"CAP_DAC_READ_SEARCH"}),
    "T17": ("dd", "/dev/mem", {"CAP_SYS_RAWIO"}),
    "T18": (None, "/host/root/.ssh/authorized_keys", set()),
    "T19": (None, "/host/etc/ld.so.preload", set()),
    "T20": ("crontab", "/host/etc/cron.d/payload", set()),
    "T21": ("kubectl", "kubernetes.default.svc", set()),
    "T22": (None, "userfaultfd(2)", set()),
    "T23": (None, "io_uring_setup(2)", set()),
    "T24": ("cat", "/proc/1/environ", set()),
    "T25": ("nsenter", "/proc/1/ns/pid", {SYS_ADMIN}),
}

VARIANTS = (
    "baseline",
    "stale-capability",
    "post-exec-privilege",
    "renamed-binary",
    "missing-parent",
    "allowlisted-image",
    "toctou-mismatch",
    "benign-lookalike",
)


@dataclass
class SecEvent:
    id: str
    technique_id: str
    technique_name: str
    variant: str
    malicious: bool
    observable: Observable
    proc_name: str
    parent_name: str | None
    image: str
    privileged_launch: bool
    cap_effective: set[str] = field(default_factory=set)
    cap_at_exec: set[str] = field(default_factory=set)
    lsm_hook: str | None = None
    syscall_path: str = ""
    lsm_path: str | None = None
    host_ns: bool = False
    expected_name: str | None = None

    @property
    def cap_ok(self) -> bool:
        return bool(self.cap_effective)

    @property
    def snapshot_ok(self) -> bool:
        return bool(self.cap_at_exec)

    @property
    def identity_ok(self) -> bool:
        return self.image not in {"trusted.example/infra-agent", "kube-system/cni"}

    @property
    def parent_ok(self) -> bool:
        return self.parent_name not in (None, "N/A", "<NA>")

    @property
    def name_ok(self) -> bool:
        if self.expected_name is None:
            return True
        return self.proc_name == self.expected_name

    @property
    def cross_layer_ok(self) -> bool:
        if self.lsm_hook is None or self.lsm_path is None:
            return False
        return self.lsm_path == self.syscall_path


def _observable(tech: "Technique") -> Observable:
    # use the most specific single observable for the synthetic event
    priority = [
        Observable.HOST_CONFIG_WRITE, Observable.MODULE_LOAD, Observable.BPF_LOAD,
        Observable.MEMFD_EXEC, Observable.PIPE_SPLICE, Observable.PTRACE,
        Observable.NAMESPACE_ENTRY, Observable.MOUNT, Observable.CREDENTIAL_CHANGE,
        Observable.DEVICE_ACCESS, Observable.MEMORY_FAULT, Observable.IO_URING,
        Observable.CREDENTIAL_READ, Observable.UNIX_SOCKET, Observable.EXEC,
        Observable.OPEN_FILE, Observable.FILE_READ, Observable.FILE_WRITE,
    ]
    for o in priority:
        if o in tech.observables:
            return o
    return next(iter(tech.observables))


def generate_events() -> list[SecEvent]:
    events: list[SecEvent] = []
    for tech in TECHNIQUES:
        expected, path, caps = META.get(tech.id, (None, "", set()))
        obs = _observable(tech)
        lsm_hook = {
            Observable.EXEC: "bprm_check_security",
            Observable.FILE_WRITE: "security_file_open",
            Observable.HOST_CONFIG_WRITE: "security_file_open",
            Observable.MOUNT: "security_sb_mount",
            Observable.OPEN_FILE: "security_file_open",
            Observable.FILE_READ: "security_file_open",
        }.get(obs, "security_task_setscheduler")

        def make(variant: str, malicious: bool) -> SecEvent:
            proc = expected or "payload"
            parent = "containerd-shim" if malicious else "systemd"
            image = "tenant/workload:latest"
            privileged = False
            cap_eff = set(caps)
            cap_exec = set(caps)
            lsm = lsm_hook if malicious else lsm_hook
            target_path = path
            lsm_path = target_path
            name = proc

            if variant == "stale-capability":
                cap_eff = set()
            elif variant == "post-exec-privilege":
                cap_exec = set()
            elif variant == "renamed-binary":
                name = "renamed-payload"
            elif variant == "missing-parent":
                parent = "N/A"
            elif variant == "allowlisted-image":
                image = "trusted.example/infra-agent"
            elif variant == "toctou-mismatch":
                lsm_path = "/benign/looks/ok"
            elif variant == "benign-lookalike":
                image = "trusted.example/infra-agent"
                cap_eff, cap_exec = set(), set()
                lsm = lsm_hook
                # Same observable class, but a legitimate target path: a
                # signature detector should be able to separate the two.
                target_path = "/srv/application/config"
                lsm_path = target_path

            return SecEvent(
                id=f"{tech.id}-{variant}",
                technique_id=tech.id,
                technique_name=tech.name,
                variant=variant,
                malicious=malicious,
                observable=obs,
                proc_name=name,
                parent_name=parent,
                image=image,
                privileged_launch=privileged,
                cap_effective=cap_eff,
                cap_at_exec=cap_exec,
                lsm_hook=lsm,
                syscall_path=target_path,
                lsm_path=lsm_path,
                host_ns=malicious,
                expected_name=expected,
            )

        for variant in VARIANTS:
            events.append(make(variant, malicious=variant != "benign-lookalike"))
    return events


if __name__ == "__main__":
    ev = generate_events()
    print(f"{len(ev)} events, {len(VARIANTS)} variants x {len(TECHNIQUES)} techniques")
