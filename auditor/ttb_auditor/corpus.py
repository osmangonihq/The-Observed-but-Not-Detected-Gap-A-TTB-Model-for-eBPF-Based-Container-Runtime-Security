"""Curated corpus of container-escape primitives.

Selection criteria
------------------
1. The primitive has been publicly demonstrated against Linux containers.
2. It produces kernel-visible events that all three studied tools are designed
   to observe (syscalls, tracepoints or LSM hooks) -- i.e. the *observation*
   precondition of the Detection-Trust Boundary holds.
3. Typical detections in the wild rely on at least one trust anchor, making the
   primitive informative for the audit.

This is a static policy-analysis corpus.  It does NOT claim to be a benchmark
of live exploitation, and no exploit code is included.
"""

from __future__ import annotations

from .model import Observable, Technique

TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        id="T01",
        name="cgroup v1 release_agent overwrite",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN or writable cgroup fs",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Writing a payload path into a cgroup v1 release_agent file and "
            "triggering notify_on_release executes the payload in the host "
            "context when a cgroup becomes empty."
        ),
        variants=("shell echo", "python open().write()", "custom static binary", "O_PATH + write"),
    ),
    Technique(
        id="T02",
        name="core_pattern pipe escape",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Overwriting /proc/sys/kernel/core_pattern with a pipe handler "
            "causes the kernel to execute the handler as root on the next crash."
        ),
        variants=("echo '|/tmp/payload'", "python", "dd", "custom binary"),
    ),
    Technique(
        id="T03",
        name="modprobe_path overwrite",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Changing /proc/sys/kernel/modprobe to a container-controlled path "
            "makes the kernel invoke that binary for unknown binary formats."
        ),
        variants=("write(2)", "python", "custom loader"),
    ),
    Technique(
        id="T04",
        name="debugfs mount abuse",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.MOUNT}),
        name_dependent=True,
        description=(
            "Mounting debugfs and abusing its writable kernel interfaces to "
            "reach host state.  Frequently performed by the debugfs utility, "
            "but the mount itself is tool-independent."
        ),
        variants=("debugfs", "mount -t debugfs", "mount(2) via libc", "busybox mount"),
    ),
    Technique(
        id="T05",
        name="host mount namespace entry via /proc/<pid>/ns",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.NAMESPACE_ENTRY}),
        name_dependent=False,
        description=(
            "Opening /proc/1/ns/mnt (or pid/uts/ipc) and calling setns(2) to "
            "join host namespaces, then reading host files via the new mount ns."
        ),
        variants=("nsenter", "setns(2)", "python ctypes", "custom binary"),
    ),
    Technique(
        id="T06",
        name="host root filesystem via chroot/pivot_root",
        mitre="T1611",
        required_privilege="CAP_SYS_CHROOT / CAP_SYS_ADMIN",
        observables=frozenset({Observable.MOUNT, Observable.NAMESPACE_ENTRY}),
        name_dependent=False,
        description=(
            "After obtaining a handle to /proc/1/root, chroot or pivot_root "
            "into the host filesystem and escape the container root."
        ),
        variants=("chroot", "pivot_root", "mount --bind", "busybox"),
    ),
    Technique(
        id="T07",
        name="exposed Docker socket / container API abuse",
        mitre="T1610",
        required_privilege="mounted /var/run/docker.sock",
        observables=frozenset({Observable.UNIX_SOCKET, Observable.EXEC}),
        name_dependent=True,
        description=(
            "Creating a privileged container through a mounted Docker socket "
            "or Kubernetes API, then entering the host."
        ),
        variants=("docker CLI", "curl on unix socket", "python requests-unixsocket"),
    ),
    Technique(
        id="T08",
        name="Dirty Pipe (CVE-2022-0847) overwrite",
        mitre="T1068",
        required_privilege="unprivileged (kernel bug)",
        observables=frozenset({Observable.PIPE_SPLICE}),
        name_dependent=False,
        description=(
            "Using pipe/splice to overwrite read-only files (e.g. a setuid "
            "binary or /etc/passwd) to escalate and escape."
        ),
        variants=("public PoC", "rewritten PoC", "in-memory loader"),
        cve="CVE-2022-0847",
    ),
    Technique(
        id="T09",
        name="post-exec credential change (setuid/capset)",
        mitre="T1068",
        required_privilege="initial unprivileged context",
        observables=frozenset({Observable.CREDENTIAL_CHANGE}),
        name_dependent=False,
        description=(
            "Process starts with benign credentials, then calls setuid(0), "
            "setgid or capset to gain privileges.  Tools that snapshot "
            "credentials only at exec time continue to report the benign state."
        ),
        variants=("setuid(2)", "capset(2)", "setresuid(2)", "pthread credential race"),
    ),
    Technique(
        id="T10",
        name="TOCTOU argument swap at exec",
        mitre="T1059",
        required_privilege="unprivileged",
        observables=frozenset({Observable.EXEC}),
        name_dependent=False,
        description=(
            "Changing the execve argument buffer after the eBPF sensor reads "
            "it but before the kernel consumes it, so telemetry records a "
            "benign path while a different binary executes."
        ),
        variants=("argv rewrite", "userspace mem race", "LD_PRELOAD shim"),
    ),
    Technique(
        id="T11",
        name="kernel module load",
        mitre="T1547.006",
        required_privilege="CAP_SYS_MODULE",
        observables=frozenset({Observable.MODULE_LOAD}),
        name_dependent=False,
        description=(
            "init_module(2)/finit_module(2) to load a module that disables "
            "namespace isolation or the monitoring agent itself."
        ),
        variants=("insmod", "modprobe", "finit_module", "custom loader"),
    ),
    Technique(
        id="T12",
        name="eBPF-based monitor subversion",
        mitre="T1622",
        required_privilege="CAP_BPF / CAP_SYS_ADMIN",
        observables=frozenset({Observable.BPF_LOAD}),
        name_dependent=False,
        description=(
            "Loading a privileged BPF program to patch maps, hide processes "
            "or detach the security agent's programs."
        ),
        variants=("bpftool", "libbpf", "raw bpf(2)", "perf_event_open kprobe"),
    ),
    Technique(
        id="T13",
        name="ptrace / process memory injection into host process",
        mitre="T1055.008",
        required_privilege="CAP_SYS_PTRACE or shared UID",
        observables=frozenset({Observable.PTRACE}),
        name_dependent=True,
        description=(
            "PTRACE_POKETEXT/ATTACH or process_vm_writev against a host process "
            "to execute code outside the container."
        ),
        variants=("gdb", "ptrace(2)", "process_vm_writev", "custom injector"),
    ),
    Technique(
        id="T14",
        name="fileless execution via memfd",
        mitre="T1620",
        required_privilege="unprivileged",
        observables=frozenset({Observable.MEMFD_EXEC}),
        name_dependent=False,
        description=(
            "memfd_create + execveat to run a payload with no on-disk artifact, "
            "commonly used as the second stage of an escape chain."
        ),
        variants=("memfd_create", "memfd_secret", "shm_open + fexecve"),
    ),
    Technique(
        id="T15",
        name="bind-mount host root from /proc/1/root",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.MOUNT}),
        name_dependent=False,
        description=(
            "Mounting /proc/1/root into the container mount namespace and "
            "pivoting into it to obtain an unconstrained view of the host "
            "filesystem."
        ),
        variants=("mount --bind", "mount(2)", "busybox mount"),
    ),
    Technique(
        id="T16",
        name="open_by_handle_at with CAP_DAC_READ_SEARCH",
        mitre="T1611",
        required_privilege="CAP_DAC_READ_SEARCH",
        observables=frozenset({Observable.OPEN_FILE, Observable.FILE_READ}),
        name_dependent=False,
        description=(
            "Recovering a file handle for a host path and using "
            "open_by_handle_at to read host files (including credentials) "
            "despite the container mount namespace."
        ),
        variants=("name_to_handle_at", "open_by_handle_at", "custom C helper"),
    ),
    Technique(
        id="T17",
        name="raw device access via /dev/mem or /dev/kmem",
        mitre="T1068",
        required_privilege="CAP_SYS_RAWIO",
        observables=frozenset({Observable.DEVICE_ACCESS, Observable.FILE_READ}),
        name_dependent=False,
        description=(
            "Reading or writing physical memory through exposed raw devices "
            "to locate and modify kernel state from inside the container."
        ),
        variants=("dd on /dev/mem", "mmap", "custom reader"),
    ),
    Technique(
        id="T18",
        name="host SSH authorized_keys injection",
        mitre="T1098.004",
        required_privilege="writable host mount",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Appending an attacker key to /root/.ssh/authorized_keys on a "
            "bind-mounted host filesystem to obtain persistent host access."
        ),
        variants=("echo >>", "python", "editor"),
    ),
    Technique(
        id="T19",
        name="/etc/ld.so.preload modification on host mount",
        mitre="T1574.006",
        required_privilege="writable host mount",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Writing a malicious library path into the host's "
            "/etc/ld.so.preload through a writable mount, so subsequently "
            "started host processes load the attacker library."
        ),
        variants=("echo", "python", "tee"),
    ),
    Technique(
        id="T20",
        name="host cron / systemd unit modification",
        mitre="T1053.003",
        required_privilege="writable host mount",
        observables=frozenset({Observable.HOST_CONFIG_WRITE}),
        name_dependent=False,
        description=(
            "Creating a host cron job or systemd unit through a writable "
            "bind mount to execute a payload with host privileges."
        ),
        variants=("crontab", "systemctl", "direct file write"),
    ),
    Technique(
        id="T21",
        name="service-account token theft and privileged pod creation",
        mitre="T1078.004",
        required_privilege="mounted service-account token",
        observables=frozenset({Observable.UNIX_SOCKET, Observable.EXEC}),
        name_dependent=False,
        description=(
            "Reading the mounted Kubernetes service-account token and using "
            "the API server to create a privileged pod on the node."
        ),
        variants=("kubectl", "curl", "client-go"),
    ),
    Technique(
        id="T22",
        name="userfaultfd-based kernel exploitation",
        mitre="T1068",
        required_privilege="unprivileged (kernel config dependent)",
        observables=frozenset({Observable.MEMORY_FAULT}),
        name_dependent=False,
        description=(
            "Using userfaultfd to control the timing of kernel page faults "
            "and win a race in a kernel subsystem, obtaining host execution."
        ),
        variants=("userfaultfd(2)", "ioctl UFFDIO_*", "custom PoC"),
    ),
    Technique(
        id="T23",
        name="io_uring kernel interface abuse",
        mitre="T1068",
        required_privilege="unprivileged (kernel version dependent)",
        observables=frozenset({Observable.IO_URING}),
        name_dependent=False,
        description=(
            "Exploiting memory-management bugs in the io_uring interface to "
            "corrupt kernel state and escape the container."
        ),
        variants=("io_uring_setup", "IORING_OP_*", "liburing"),
    ),
    Technique(
        id="T24",
        name="host credential harvesting from /proc/<pid>/environ",
        mitre="T1552",
        required_privilege="host PID namespace or shared UID",
        observables=frozenset({Observable.CREDENTIAL_READ}),
        name_dependent=False,
        description=(
            "Reading environment variables of a host process to obtain tokens "
            "or credentials that authorize a host-level action."
        ),
        variants=("cat /proc/1/environ", "python", "gdb"),
    ),
    Technique(
        id="T25",
        name="namespace file descriptor confusion",
        mitre="T1611",
        required_privilege="CAP_SYS_ADMIN",
        observables=frozenset({Observable.NAMESPACE_ENTRY, Observable.OPEN_FILE}),
        name_dependent=False,
        description=(
            "Retaining and reusing namespace file descriptors across process "
            "lifetimes to re-enter a host namespace after the original "
            "monitoring state has been lost."
        ),
        variants=("setns(2)", "nsenter", "fd passing"),
    ),
)


BY_ID = {t.id: t for t in TECHNIQUES}


def corpus_summary() -> dict[str, int]:
    return {
        "techniques": len(TECHNIQUES),
        "name_dependent": sum(t.name_dependent for t in TECHNIQUES),
        "cve_linked": sum(t.cve is not None for t in TECHNIQUES),
        "observable_classes": len({o for t in TECHNIQUES for o in t.observables}),
    }
