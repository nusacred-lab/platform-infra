"""Build the private P2 candidates from pinned images and source bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

MAILPIT_COMMIT = "4355c8cd7dbe745c6fc6ce8619d23a1a31b746c9"
MAILPIT_ARCHIVE_SHA256 = "8d8b2a6d26eb4cd61746a2f00fa08d719a155faaea24aff6158db6dec8439541"


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--mail-only", action="store_true", help="Build only the checksum-pinned Mailpit source for P6")
    parser.add_argument("--mail-pin", type=Path, help="Use the reviewed P6 Mailpit source pin and build recipe")
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if "runtime" not in runtime.parts:
        parser.error("Use an ignored private runtime directory.")
    runtime.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    mail = json.loads(args.mail_pin.read_text()) if args.mail_pin else {
        "commit": MAILPIT_COMMIT, "archiveSha256": MAILPIT_ARCHIVE_SHA256,
        "version": "1.31.5", "containerfile": "p2/Containerfile.mailpit"}
    images = json.loads((root / "p2/images.json").read_text())
    for kind, version in (() if args.mail_only else (("keycloak", "26.8.1"), ("postgres", "18.6"))):
        run("docker", "build", "--build-arg", f"{kind.upper()}_IMAGE={images[kind]}",
            "-f", str(root / f"p2/Containerfile.{kind}"),
            "-t", f"competency-proof-p2-{kind}:{version}", str(root / "p2"))
    archive = runtime / (f"mailpit-{mail['commit']}.tar.gz" if args.mail_pin else "mailpit-source.tar.gz")
    if not archive.exists():
        urllib.request.urlretrieve(
            f"https://codeload.github.com/axllent/mailpit/tar.gz/{mail['commit']}", archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != mail['archiveSha256']:
        raise SystemExit("Mailpit source checksum does not match the reviewed archive.")
    sources = runtime / "source"
    sources.mkdir(exist_ok=True)
    with tarfile.open(archive) as source:
        source.extractall(sources, filter="data")
    project = sources / f"mailpit-{mail['commit']}"
    run("npm", "ci", "--ignore-scripts", "--cache", str(runtime / "npm-cache"), cwd=project)
    run("npm", "run", "package", cwd=project)
    run("docker", "build", "-f", str(root / mail['containerfile']),
        "-t", f"competency-proof-p2-mailpit:{mail['version']}", str(project))
    print("Built candidates. Run check_p2_images.py before preparing runtime image IDs.")


if __name__ == "__main__":
    main()
