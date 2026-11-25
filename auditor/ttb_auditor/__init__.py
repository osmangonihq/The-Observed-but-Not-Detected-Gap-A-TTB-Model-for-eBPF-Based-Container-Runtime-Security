"""Telemetry-Trust Boundary (TTB) auditor.

A static policy auditor that exposes the gap between kernel-level observation
and policy-level detection in eBPF container runtime security tools.
"""

from .engine import audit_directory, audit_policy_file
from .model import RuleAudit, ToolAudit, TechniqueVerdict, Finding, TrustClass
from .report import to_dict, write_json, write_markdown

__all__ = [
    "audit_directory",
    "audit_policy_file",
    "RuleAudit",
    "ToolAudit",
    "TechniqueVerdict",
    "Finding",
    "TrustClass",
    "to_dict",
    "write_json",
    "write_markdown",
]
__version__ = "1.0.0"
