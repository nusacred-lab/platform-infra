"""Install a reviewed Linux x86_64 scanner into a temporary directory."""
import hashlib, io, json, pathlib, sys, tarfile, urllib.request
name = sys.argv[1]
config = json.loads(pathlib.Path("ci/tools.json").read_text())[name]
with urllib.request.urlopen(config["url"], timeout=120) as response:
    payload = response.read()
if hashlib.sha256(payload).hexdigest() != config["sha256"]:
    raise SystemExit("Scanner checksum mismatch")
dest = pathlib.Path(sys.argv[2]); dest.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
    member = archive.getmember(name)
    if not member.isfile(): raise SystemExit("Unexpected scanner archive")
    binary = archive.extractfile(member).read()
output = dest / name; output.write_bytes(binary); output.chmod(0o755)
print(name + " verified: " + config["version"])
