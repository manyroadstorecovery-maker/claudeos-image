"""Build step: image signature policy. Only ClaudeOS-signed images may be installed as ClaudeOS;
every other image (Toolbox, Podman) is accepted exactly as on stock Fedora.
The update tool only checks signatures when the overall default is "reject", hence the explicit
"accept" for every transport."""
import json

IMAGE = "ghcr.io/manyroadstorecovery-maker/claudeos-image"
src, dst = "/usr/share/containers/policy.json", "/etc/containers/policy.json"
pol = json.load(open(src))
pol["default"] = [{"type": "reject"}]
tr = pol.setdefault("transports", {})
for t in ("docker", "docker-daemon", "containers-storage", "oci", "oci-archive", "docker-archive",
          "dir", "sif", "tarball"):
    tr.setdefault(t, {}).setdefault("", [{"type": "insecureAcceptAnything"}])
tr["docker"][IMAGE] = [{
    "type": "sigstoreSigned", "keyPath": "/etc/pki/containers/claudeos-image.pub",
    "signedIdentity": {"type": "matchRepository"}}]
with open(dst, "w") as f:
    json.dump(pol, f, indent=2)
print("policy:", dst)
