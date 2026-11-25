# Detection-Trust Boundary — policy audit report

Static analysis of upstream policy files. No live exploitation is implied.

## Falco

- Policy files analysed: 3
- Normalized rules: 96
- Findings: 170
- Mean Trust Dependency Score: 0.232
- Gap ratio (observed-but-not-detected / covered): 56.5%

| Technique | Classification | Best TDS | Covering rules |
|---|---|---:|---|
| T01 cgroup v1 release_agent overwrite | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T02 core_pattern pipe escape | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T03 modprobe_path overwrite | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T04 debugfs mount abuse | detected | 0.00 | Mount Launched in Privileged Container, Launch Sensitive Mount Container, Debugfs Launched in Privileged Container |
| T05 host mount namespace entry via /proc/<pid>/ns | observed-not-detected | 0.48 | Change thread namespace |
| T06 host root filesystem via chroot/pivot_root | detected | 0.00 | Change thread namespace, Mount Launched in Privileged Container, Launch Sensitive Mount Container |
| T07 exposed Docker socket / container API abuse | detected | 0.00 | Schedule Cron Jobs, DB program spawned process, Program run with disallowed http proxy env |
| T08 Dirty Pipe (CVE-2022-0847) overwrite | no-rule | — | — |
| T09 post-exec credential change (setuid/capset) | observed-not-detected | 0.30 | Non sudo setuid, Set Setuid or Setgid bit, Container Run as Root User |
| T10 TOCTOU argument swap at exec | observed-not-detected | 0.16 | Schedule Cron Jobs, DB program spawned process, Program run with disallowed http proxy env |
| T11 kernel module load | observed-not-detected | 0.33 | Linux Kernel Module Injection Detected |
| T12 eBPF-based monitor subversion | detected | 0.06 | BPF Program Not Profiled |
| T13 ptrace / process memory injection into host process | observed-not-detected | 0.18 | PTRACE attached to process, PTRACE anti-debug attempt |
| T14 fileless execution via memfd | observed-not-detected | 0.16 | Fileless execution via memfd_create |
| T15 bind-mount host root from /proc/1/root | detected | 0.00 | Mount Launched in Privileged Container, Launch Sensitive Mount Container, Debugfs Launched in Privileged Container |
| T16 open_by_handle_at with CAP_DAC_READ_SEARCH | detected | 0.00 | Modify Shell Configuration File, Modify Python Startup Hook File, Schedule Cron Jobs |
| T17 raw device access via /dev/mem or /dev/kmem | detected | 0.00 | Launch Excessively Capable Container, Privileged Container Device Access |
| T18 host SSH authorized_keys injection | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T19 /etc/ld.so.preload modification on host mount | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T20 host cron / systemd unit modification | observed-not-detected | 0.39 | Schedule Cron Jobs, Adding ssh keys to authorized_keys, Detect release_agent File Container Escapes |
| T21 service-account token theft and privileged pod creation | detected | 0.00 | Schedule Cron Jobs, DB program spawned process, Program run with disallowed http proxy env |
| T22 userfaultfd-based kernel exploitation | observed-not-detected | 0.30 | Unprivileged Delegation of Page Faults Handling to a Userspace Process |
| T23 io_uring kernel interface abuse | no-rule | — | — |
| T24 host credential harvesting from /proc/<pid>/environ | detected | 0.00 | Read environment variable from /proc files, Write below etc |
| T25 namespace file descriptor confusion | detected | 0.00 | Modify Shell Configuration File, Modify Python Startup Hook File, Schedule Cron Jobs |

### Trust-anchor distribution

- `telemetry-state`: 5
- `signature-name`: 32
- `identity-allowlist`: 60
- `cross-layer`: 62
- `privilege-attribute`: 8
- `temporal-scope`: 3

### Highest-trust-dependency rules

- `Mount Launched in Privileged Container` — TDS 0.61 [TB-01, TB-02, TB-04, TB-05] — falco-incubating_rules.yaml
- `Read sensitive file untrusted` — TDS 0.57 [TB-02, TB-03, TB-04, TB-05] — falco_rules.yaml
- `Debugfs Launched in Privileged Container` — TDS 0.54 [TB-01, TB-04, TB-05] — falco_rules.yaml
- `Non sudo setuid` — TDS 0.52 [TB-01, TB-02, TB-04, TB-05] — falco-incubating_rules.yaml
- `Adding ssh keys to authorized_keys` — TDS 0.50 [TB-02, TB-04, TB-05] — falco-incubating_rules.yaml
- `Change thread namespace` — TDS 0.48 [TB-02, TB-03, TB-04, TB-05] — falco-incubating_rules.yaml
- `Container Run as Root User` — TDS 0.45 [TB-01, TB-02, TB-05] — falco-sandbox_rules.yaml
- `Detect release_agent File Container Escapes` — TDS 0.42 [TB-01, TB-05, TB-06] — falco_rules.yaml
- `Write below root` — TDS 0.41 [TB-02, TB-03, TB-05] — falco-sandbox_rules.yaml
- `Modify Shell Configuration File` — TDS 0.39 [TB-02, TB-04, TB-05] — falco-incubating_rules.yaml

## Tetragon

- Policy files analysed: 69
- Normalized rules: 109
- Findings: 142
- Mean Trust Dependency Score: 0.130
- Gap ratio (observed-but-not-detected / covered): 23.1%

| Technique | Classification | Best TDS | Covering rules |
|---|---|---:|---|
| T01 cgroup v1 release_agent overwrite | no-rule | — | — |
| T02 core_pattern pipe escape | no-rule | — | — |
| T03 modprobe_path overwrite | no-rule | — | — |
| T04 debugfs mount abuse | detected | 0.06 | syscalls/kprobes[0]:sys_mount, sys-pivot-root/kprobes[0]:sys_pivot_root |
| T05 host mount namespace entry via /proc/<pid>/ns | observed-not-detected | 0.24 | fd-install/kprobes[0]:fd_install, fd-install/kprobes[0]:fd_install |
| T06 host root filesystem via chroot/pivot_root | detected | 0.06 | fd-install/kprobes[0]:fd_install, fd-install/kprobes[0]:fd_install, syscalls/kprobes[0]:sys_mount |
| T07 exposed Docker socket / container API abuse | detected | 0.00 | lsm/lsmhooks[0]:bprm_check_security, lsm/lsmhooks[0]:bprm_check_security, rawtp/tracepoints[0]:sched_process_exec |
| T08 Dirty Pipe (CVE-2022-0847) overwrite | no-rule | — | — |
| T09 post-exec credential change (setuid/capset) | detected | 0.06 | commit-creds/kprobes[0]:commit_creds, process-creds-changed/kprobes[0]:commit_creds, process-creds-changed/kprobes[1]:override_creds |
| T10 TOCTOU argument swap at exec | detected | 0.00 | lsm/lsmhooks[0]:bprm_check_security, lsm/lsmhooks[0]:bprm_check_security, rawtp/tracepoints[0]:sched_process_exec |
| T11 kernel module load | detected | 0.06 | monitor-kernel-modules/kprobes[0]:security_kernel_module_request, monitor-kernel-modules/kprobes[1]:security_kernel_read_file, monitor-kernel-modules/kprobes[2]:do_init_module |
| T12 eBPF-based monitor subversion | detected | 0.06 | bpf/kprobes[0]:bpf_check, bpf/kprobes[1]:security_perf_event_alloc, bpf/kprobes[2]:security_bpf_map_alloc |
| T13 ptrace / process memory injection into host process | detected | 0.06 | syscalls/kprobes[0]:sys_ptrace |
| T14 fileless execution via memfd | no-rule | — | — |
| T15 bind-mount host root from /proc/1/root | detected | 0.06 | syscalls/kprobes[0]:sys_mount, sys-pivot-root/kprobes[0]:sys_pivot_root |
| T16 open_by_handle_at with CAP_DAC_READ_SEARCH | observed-not-detected | 0.34 | lsm-file-open/lsmhooks[0]:file_open |
| T17 raw device access via /dev/mem or /dev/kmem | no-rule | — | — |
| T18 host SSH authorized_keys injection | no-rule | — | — |
| T19 /etc/ld.so.preload modification on host mount | no-rule | — | — |
| T20 host cron / systemd unit modification | no-rule | — | — |
| T21 service-account token theft and privileged pod creation | detected | 0.00 | lsm/lsmhooks[0]:bprm_check_security, lsm/lsmhooks[0]:bprm_check_security, rawtp/tracepoints[0]:sched_process_exec |
| T22 userfaultfd-based kernel exploitation | no-rule | — | — |
| T23 io_uring kernel interface abuse | no-rule | — | — |
| T24 host credential harvesting from /proc/<pid>/environ | no-rule | — | — |
| T25 namespace file descriptor confusion | observed-not-detected | 0.24 | fd-install/kprobes[0]:fd_install, fd-install/kprobes[0]:fd_install, lsm-file-open/lsmhooks[0]:file_open |

### Trust-anchor distribution

- `telemetry-state`: 0
- `signature-name`: 10
- `identity-allowlist`: 29
- `cross-layer`: 99
- `privilege-attribute`: 4
- `temporal-scope`: 0

### Highest-trust-dependency rules

- `kill-unprivileged-user-namespace-in-pid-namespace/kprobes[0]:create_user_ns` — TDS 0.46 [TB-01, TB-02, TB-05] — sandbox__linux-namespaces__kill_unprivileged_user_namespace_in_pid_namespace.yaml
- `cve-2024-3094-xz-ssh/kprobes[0]:security_mmap_file` — TDS 0.40 [TB-02, TB-04, TB-05] — cves__cve-2024-3094-xz-ssh.yaml
- `all-ksys-for-kill/kprobes[0]:list:ksys` — TDS 0.40 [TB-02, TB-04, TB-05] — list-generated-ftrace.yaml
- `all-syscalls-for-kill/kprobes[0]:list:all-syscalls` — TDS 0.40 [TB-02, TB-04, TB-05] — list-syscalls-generated.yaml
- `security-override/kprobes[0]:security_inode_mkdir` — TDS 0.40 [TB-02, TB-04, TB-05] — override-security.yaml
- `security-socket-connect/kprobes[0]:security_socket_connect` — TDS 0.40 [TB-02, TB-04, TB-05] — security-socket-connect-block-others.yaml
- `connect-only-local-addrs/kprobes[0]:tcp_connect` — TDS 0.40 [TB-02, TB-04, TB-05] — tcp-connect-only-local-addrs.yaml
- `kill-syscalls/tracepoints[0]:sys_enter` — TDS 0.34 [TB-02, TB-04] — killer.yaml
- `lsm/lsmhooks[0]:bprm_check_security` — TDS 0.34 [TB-02, TB-04] — lsm_bprm_check.yaml
- `lsm-file-open/lsmhooks[0]:file_open` — TDS 0.34 [TB-02, TB-04] — lsm_file_open.yaml

## Tracee

- Policy files analysed: 15
- Normalized rules: 91
- Findings: 28
- Mean Trust Dependency Score: 0.038
- Gap ratio (observed-but-not-detected / covered): 5.3%

| Technique | Classification | Best TDS | Covering rules |
|---|---|---:|---|
| T01 cgroup v1 release_agent overwrite | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T02 core_pattern pipe escape | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T03 modprobe_path overwrite | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T04 debugfs mount abuse | detected | 0.00 | signature-events/disk_mount |
| T05 host mount namespace entry via /proc/<pid>/ns | no-rule | — | — |
| T06 host root filesystem via chroot/pivot_root | detected | 0.00 | signature-events/disk_mount |
| T07 exposed Docker socket / container API abuse | detected | 0.00 | extend-default-policy/sched_process_exec, comm-strace/sched_process_exec, signature-events/k8s_api_connection |
| T08 Dirty Pipe (CVE-2022-0847) overwrite | no-rule | — | — |
| T09 post-exec credential change (setuid/capset) | detected | 0.06 | extend-default-policy/setuid |
| T10 TOCTOU argument swap at exec | observed-not-detected | 0.16 | extend-default-policy/sched_process_exec, comm-strace/sched_process_exec, comm-strace/sched_process_exec |
| T11 kernel module load | detected | 0.00 | signature-events/kernel_module_loading |
| T12 eBPF-based monitor subversion | no-rule | — | — |
| T13 ptrace / process memory injection into host process | detected | 0.00 | signature-events/ptrace_code_injection, signature-events/process_vm_write_inject |
| T14 fileless execution via memfd | detected | 0.00 | signature-events/fileless_execution |
| T15 bind-mount host root from /proc/1/root | detected | 0.00 | signature-events/disk_mount |
| T16 open_by_handle_at with CAP_DAC_READ_SEARCH | detected | 0.00 | new-containers/security_file_open, new-pids/security_file_open, signature-events/proc_kcore_read |
| T17 raw device access via /dev/mem or /dev/kmem | detected | 0.00 | signature-events/proc_kcore_read, signature-events/proc_mem_access |
| T18 host SSH authorized_keys injection | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T19 /etc/ld.so.preload modification on host mount | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T20 host cron / systemd unit modification | detected | 0.00 | signature-events/cgroup_notify_on_release, signature-events/default_loader_mod, signature-events/cgroup_release_agent |
| T21 service-account token theft and privileged pod creation | detected | 0.00 | extend-default-policy/sched_process_exec, comm-strace/sched_process_exec, signature-events/k8s_api_connection |
| T22 userfaultfd-based kernel exploitation | no-rule | — | — |
| T23 io_uring kernel interface abuse | no-rule | — | — |
| T24 host credential harvesting from /proc/<pid>/environ | no-rule | — | — |
| T25 namespace file descriptor confusion | detected | 0.00 | new-containers/security_file_open, new-pids/security_file_open, new-containers/security_file_open |

### Trust-anchor distribution

- `telemetry-state`: 5
- `signature-name`: 9
- `identity-allowlist`: 0
- `cross-layer`: 10
- `privilege-attribute`: 0
- `temporal-scope`: 4

### Highest-trust-dependency rules

- `comm-strace/sched_process_exec` — TDS 0.32 [TB-04, TB-05] — yaml__k8s__scope_comm.yaml
- `comm-strace/sched_process_exec` — TDS 0.32 [TB-04, TB-05] — yaml__plain__scope_comm.yaml
- `context-comm/openat` — TDS 0.22 [TB-04, TB-05] — yaml__k8s__context_comm.yaml
- `new-containers/container_create` — TDS 0.22 [TB-03, TB-06] — yaml__k8s__new_containers.yaml
- `new-containers/security_file_open` — TDS 0.22 [TB-03, TB-06] — yaml__k8s__new_containers.yaml
- `new-containers/container_create` — TDS 0.22 [TB-03, TB-06] — yaml__plain__new_containers.yaml
- `new-containers/security_file_open` — TDS 0.22 [TB-03, TB-06] — yaml__plain__new_containers.yaml
- `not-containers/anti_debugging` — TDS 0.18 [TB-03] — yaml__k8s__not_containers.yaml
- `dig/net_packet_dns_request` — TDS 0.16 [TB-04] — yaml__k8s__dig.yaml
- `dig/net_packet_dns_response` — TDS 0.16 [TB-04] — yaml__k8s__dig.yaml
