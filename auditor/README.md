# TTB Auditor — Detection-Trust Boundary policy auditor

Static auditor that exposes the **observed-but-not-detected** gap in eBPF
container runtime security policies. It parses real Falco, Tetragon and Tracee
policy files, normalizes them, applies six trust-boundary checks, scores each
rule with a Trust Dependency Score (TDS), and classifies a curated corpus of
container-escape primitives.

> **Scope statement.** This is a *static policy-analysis* tool. It does not
> execute exploits, does not measure runtime detection rates, and does not
> claim that any vendor product is insecure. Its purpose is to make the trust
> assumptions embedded in detection policies explicit and auditable.

## Install / run

```bash
# no third-party dependencies beyond PyYAML
python3 -m pip install pyyaml

# audit a directory of upstream policy files
python3 -m ttb_auditor.cli ../experiments/policies \
    --json ../experiments/results/audit.json \
    --markdown ../experiments/results/audit.md

# run the test suite
python3 -m unittest discover -s tests -v
```

## Model

A detection is the conjunction of an observation and a policy decision:

```
D(e) = O(e) ∧ P(e)
```

An eBPF sensor may satisfy `O(e)` for an escape primitive while `P(e)` evaluates
to false because `P` delegates to a **trust anchor** whose value is not
guaranteed by the kernel observation. The auditor enumerates six anchor classes:

| Check | Trust class | Example anchor |
|---|---|---|
| TB-01 | privilege-attribute | `container.privileged=true`, `thread.cap_effective`, `CAP_SYS_ADMIN` |
| TB-02 | identity-allowlist | `trusted_images`, `user_known_*`, `never_true` placeholders |
| TB-03 | telemetry-state | `not proc.pname exists`, `container=new`, `N/A` |
| TB-04 | signature-name | `proc.name=debugfs`, `matchBinaries`, `comm=` |
| TB-05 | cross-layer | syscall-only observation, no LSM cross-check (TOCTOU) |
| TB-06 | temporal-scope | exec-time credential snapshots, startup-fixed detector sets |

### Trust Dependency Score

```
TDS(rule) = min(1, Σ  w(class) · s(severity))
w = {privilege:0.22, allowlist:0.18, telemetry:0.18,
     signature:0.16, cross-layer:0.16, temporal:0.10}
s = {critical:1.0, high:1.0, medium:0.4, low:0.2}
```

A rule is **robust** iff it has no high/critical finding and `TDS < 0.25`.
A technique is classified as:

* `detected` — at least one robust rule covers it;
* `observed-not-detected` — covered, but every covering rule has a trust defect;
* `no-rule` — no policy rule matches the observable surface.

`gap ratio = observed-not-detected / (detected + observed-not-detected)`.

## Interpreting results

The auditor reports **structural gaps in the policy corpus it was given**. A
high ratio means that, for the analyzed files, the rules that see the relevant
syscalls condition their alert on metadata that a privileged in-container
adversary can invalidate. Results depend on the check weights and the technique
corpus; both are published with the tool so the analysis can be reproduced and
challenged. See the paper's Threats to Validity section.
