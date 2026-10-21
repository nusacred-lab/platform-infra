"""Scan immutable local P2 images, then record the accepted IDs privately."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--scanner", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--with-application", action="store_true")
    args = parser.parse_args()
    images = {
        "P2_EDGE_IMAGE": "competency-proof-local-edge:reviewed",
        "P2_POSTGRES_IMAGE": "competency-proof-p2-postgres:18.6",
        "P2_MAILPIT_IMAGE": "competency-proof-p2-mailpit:1.31.5",
        "P2_KEYCLOAK_IMAGE": "competency-proof-p2-keycloak:26.8.1",
    }
    if args.with_application:
        images["P2_CUSTODIAN_IMAGE"] = "competency-proof-p2-custodian:0.2.0"
    runtime = args.runtime.resolve()
    if "runtime" not in runtime.parts or not runtime.is_dir():
        parser.error("Prepare an ignored private runtime directory first.")
    accepted = {}
    reports = runtime / "scans"
    reports.mkdir(exist_ok=True)
    # Trivy uses an exclusive local cache lock; keep these scans sequential.
    for name, image in images.items():
        image_id = subprocess.check_output(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
        report = reports / f"{name.lower()}.json"
        subprocess.run([str(args.scanner.resolve()), "image", "--cache-dir", str(args.cache.resolve()),
                        "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--exit-code", "1",
                        "--format", "json", "--output", str(report), image_id], check=True)
        data = json.loads(report.read_text())
        if data["Metadata"]["ImageID"] != image_id or not data.get("Results"):
            raise SystemExit("Scanner coverage or image identity is missing.")
        accepted[name] = image_id
    target = runtime / "runtime-images.json"
    target.write_text(json.dumps(accepted, indent=2) + "\n")
    target.chmod(0o600)
    print(f"PASS: {len(images)} immutable runtime images have no detected High/Critical vulnerabilities.")


if __name__ == "__main__":
    main()
