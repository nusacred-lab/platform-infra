"""Check the source-control and workflow policy; exits nonzero on violations."""
from pathlib import Path
import re, subprocess
failures = []
paths = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
for name in paths:
    parts = Path(name).parts
    if any(p in {"runtime", "backups", "secrets", ".venv"} for p in parts):
        failures.append("Private runtime path tracked: " + name)
    if Path(name).name.startswith(".env") and Path(name).name != ".env.example":
        failures.append("Environment secret file tracked: " + name)
for path in Path(".github/workflows").glob("*.y*ml"):
    source = path.read_text()
    for action in re.findall(r"uses:\s*([^\s#]+)", source):
        if not re.fullmatch(r"[\w.-]+/[\w./-]+@[a-f0-9]{40}", action):
            failures.append("Unpinned action: " + str(path))
    release = path.name == "release.yml"
    if release:
        jobs = re.findall(r"^  ([a-z][a-z-]*):\n(.*?)(?=^  [a-z][a-z-]*:|\Z)", source.split("jobs:",1)[-1], re.M | re.S)
        if {name for name, body in jobs} != {"build", "publish", "assemble"}:
            failures.append("Unexpected release jobs")
        gate = "github.event_name != 'pull_request' && github.repository == 'nusacred-lab/platform-infra' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/codex/p6-release')"
        for name, body in jobs:
            if name == "build":
                if any(token in body for token in ("packages: write", "id-token: write", "attestations: write")):
                    failures.append("Privileged release builder")
            elif "    if: " + gate not in body or ("    needs: build" if name == "publish" else "    needs: [build, publish]") not in body:
                failures.append("Release privilege boundary missing: " + name)
        header = source.split("jobs:",1)[0]
        if any(token in header for token in ("packages: write", "id-token: write", "attestations: write")):
            failures.append("Global release write permissions")
    for forbidden in (("pull_request_target", "workflow_run", "secrets.", "write-all", "contents: write", "self-hosted") + (() if release else ("packages: write", "id-token: write", "attestations: write"))):
        if forbidden in source: failures.append("Privileged CI pattern: " + forbidden)
if not Path("LICENSE").is_file(): failures.append("Missing license")
if Path("ci/gate-negative-fixture.txt").exists():
    failures.append("Intentional negative gate fixture")
if failures: raise SystemExit("\n".join(failures))
print("PASS: source paths, action pins and read-only CI and restricted release policy")
