"""Expand the frozen policy corpus from public upstream repositories.

Uses the public GitHub trees API (no authentication required, rate limited).
Only installs policy/signature files for the three tools already studied.
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "experiments" / "policies"

REPOS = {
    "falcosecurity/rules": ("Falco", "rules/"),
    "falcosecurity/falco-extras": ("Falco", "rules/"),
    "cilium/tetragon": ("Tetragon", "examples/tracingpolicy/"),
    "aquasecurity/tracee": ("Tracee", "examples/policies/"),
}


def api(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "ttb-audit-research"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def raw(repo: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "ttb-audit-research"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> None:
    manifest = []
    for repo, (tool, prefix) in REPOS.items():
        try:
            tree = api(f"https://api.github.com/repos/{repo}/git/trees/main?recursive=1")
        except Exception as exc:  # pragma: no cover - network guard
            print(f"SKIP tree {repo}: {exc}")
            continue
        paths = [
            e["path"] for e in tree.get("tree", [])
            if e.get("type") == "blob"
            and e["path"].startswith(prefix)
            and e["path"].endswith((".yaml", ".yml"))
        ]
        print(f"{repo}: {len(paths)} candidate policy files")
        target_dir = DEST / tool.lower() / "extra"
        target_dir.mkdir(parents=True, exist_ok=True)
        saved = 0
        for path in paths:
            name = path[len(prefix):].replace("/", "__")
            out = target_dir / name
            if out.exists():
                continue
            try:
                content = raw(repo, path)
            except Exception as exc:  # pragma: no cover
                print(f"  skip {path}: {exc}")
                continue
            if tool == "Falco" and "- rule:" not in content:
                continue
            out.write_text(content, encoding="utf-8")
            saved += 1
            manifest.append({"repo": repo, "path": path, "tool": tool, "local": str(out)})
        print(f"  saved {saved}")
        time.sleep(1)

    (ROOT / "experiments" / "results" / "policy_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"Manifest: {len(manifest)} files")


if __name__ == "__main__":
    main()
