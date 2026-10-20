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
    for forbidden in ("pull_request_target", "workflow_run", "secrets.", "write-all", "packages: write", "contents: write", "id-token: write", "self-hosted"):
        if forbidden in source: failures.append("Privileged CI pattern: " + forbidden)
if not Path("LICENSE").is_file(): failures.append("Missing license")
if Path("ci/gate-negative-fixture.txt").exists():
    failures.append("Intentional negative gate fixture")
if failures: raise SystemExit("\n".join(failures))
print("PASS: source paths, action pins and read-only CI policy")
