# Live testbed (setup notes)

The live study used a Fedora 42 Cloud KVM VM with a kind v0.33.0 cluster (Kubernetes v1.37.0) and three runtime agents: Tetragon v1.7.1, Falco 0.45.2 and Tracee (image digest prefix c83ce5aa). The reproducible manifests are in `../testbed/manifests/` and the PoC sources in `../testbed/poc/`.

Large VM disk images, local image tarballs and machine-specific login helpers are intentionally not published. To reproduce, provision a VM with at least 16 GB of disk and 4 GB RAM, install kind/Kubernetes, load the agent images listed in `../README.md`, and apply the manifests in dependency order: Tetragon, then Falco/Tracee, then the workload pods. Set your own VM password; none is stored in this repository.

Kernel configuration used: Linux 6.14, cgroup v2, BTF available at `/sys/kernel/btf/vmlinux`, `unprivileged_bpf_disabled=2`. Because the kernel is cgroup v2, the cgroup-v1 `release_agent` primitive was not runnable.
