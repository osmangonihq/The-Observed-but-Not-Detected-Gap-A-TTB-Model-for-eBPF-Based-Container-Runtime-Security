"""DTB-Harden: turn a static trust-anchor finding into an event-time guard.

For each privileged/host-config anchor, the transformer emits a Tetragon
TracingPolicy that re-validates at the kernel hook instead of relying on the
launch-time or path-selector state that created the gap. This is the
mechanism evaluated in §6.7 of the manuscript.
"""
from __future__ import annotations

import json
from pathlib import Path

PATHS = [
    '/proc/sys/kernel/core_pattern',
    '/proc/sys/kernel/modprobe',
    '/proc/1/root',
    '/var/run/docker.sock',
]
CRED_HOOKS = ['__x64_sys_capset', '__x64_sys_setuid', '__x64_sys_setns']

def build() -> tuple[str, str]:
    """Tetragon rejects a policy mixing LSM hooks and kprobes; emit two files."""
    lsm = [
        'apiVersion: cilium.io/v1alpha1', 'kind: TracingPolicy', 'metadata:',
        '  name: dtb-hardened-lsm', 'spec:', '  lsmhooks:',
        '  - hook: "file_open"', '    args:', '    - index: 0', '      type: "file"',
        '    selectors:', '    - matchArgs:', '      - index: 0',
        '        operator: "Prefix"', '        values:',
    ] + [f'        - "{x}"' for x in PATHS] + [
        '      matchActions:', '      - action: Post',
    ]
    kp = [
        'apiVersion: cilium.io/v1alpha1', 'kind: TracingPolicy', 'metadata:',
        '  name: dtb-hardened-cred', 'spec:', '  kprobes:',
    ]
    for h in CRED_HOOKS:
        kp += [f'  - call: "{h}"', '    syscall: true', '    selectors:',
               '    - matchActions:', '      - action: Post']
    return '\n'.join(lsm) + '\n', '\n'.join(kp) + '\n'

def main() -> None:
    root = Path(__file__).resolve().parents[2]
    out = root / 'testbed' / 'policies'
    out.mkdir(parents=True, exist_ok=True)
    lsm, kp = build()
    (out/'dtb_hardened_lsm.yaml').write_text(lsm)
    (out/'dtb_hardened_cred.yaml').write_text(kp)
    print(out/'dtb_hardened_lsm.yaml', out/'dtb_hardened_cred.yaml')

if __name__ == '__main__':
    main()
