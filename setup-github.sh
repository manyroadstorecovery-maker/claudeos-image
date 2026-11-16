#!/usr/bin/env bash
# ClaudeOS image — one-time GitHub setup. Run it yourself in a terminal (no sudo):
#   bash ~/claudeos-image/setup-github.sh
# It will:
#   1. download GitHub's `gh` and Sigstore's `cosign` tools into ~/.local/bin (checksums verified)
#   2. sign you in to GitHub (a browser window opens; type the code it shows)
#   3. make two key pairs in a private temporary folder:
#        - Secure Boot key: signs the NVIDIA driver so your PC will load it
#        - image key: signs every ClaudeOS image so your PC rejects fakes
#      The PRIVATE halves go straight into the repo's encrypted GitHub secrets and are then
#      shredded here. The PUBLIC halves go into the repo (certs/claudeos-mok.der, cosign.pub).
#   4. create the PUBLIC repo github.com/<you>/claudeos-image and push this folder
#      (Containerfile, workflow, README, public keys; nothing personal), which starts the first build.
set -euo pipefail
cd "$(dirname "$0")"
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
TMP="$(mktemp -d)"; chmod 700 "$TMP"; trap 'find "$TMP" -type f -exec shred -u {} +; rm -rf "$TMP"' EXIT
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
latest() { curl -fsSL "https://api.github.com/repos/$1/releases/latest" | python3 -I -c "import json,sys;print(json.load(sys.stdin)['tag_name'].lstrip('v'))"; }

step "1/4  Tools"
if ! command -v gh >/dev/null; then
  V=$(latest cli/cli); F="gh_${V}_linux_amd64.tar.gz"
  curl -fsSL -o "$TMP/$F" "https://github.com/cli/cli/releases/download/v$V/$F"
  curl -fsSL -o "$TMP/sums" "https://github.com/cli/cli/releases/download/v$V/gh_${V}_checksums.txt"
  (cd "$TMP" && grep " $F\$" sums | sha256sum -c)
  tar -xzf "$TMP/$F" -C "$TMP" && install -m 0755 "$TMP/gh_${V}_linux_amd64/bin/gh" "$BIN/gh"
fi
if ! command -v cosign >/dev/null; then
  V=$(latest sigstore/cosign)
  curl -fsSL -o "$TMP/cosign-linux-amd64" "https://github.com/sigstore/cosign/releases/download/v$V/cosign-linux-amd64"
  curl -fsSL -o "$TMP/sums" "https://github.com/sigstore/cosign/releases/download/v$V/cosign_checksums.txt"
  (cd "$TMP" && grep " cosign-linux-amd64\$" sums | sha256sum -c)
  install -m 0755 "$TMP/cosign-linux-amd64" "$BIN/cosign"
fi
gh --version | head -n1; cosign version 2>&1 | grep -m1 GitVersion

step "2/4  GitHub sign-in"
gh auth status >/dev/null 2>&1 || gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
OWNER="$(gh api user --jq .login)"; echo "Signed in as $OWNER"

step "3/4  Keys"
if [ -f certs/claudeos-mok.der ] && [ -f cosign.pub ]; then
  echo "Keys already made (certs/claudeos-mok.der, cosign.pub); keeping them."
  NEWKEYS=0
else
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
    -subj "/CN=ClaudeOS NVIDIA module signing key/" \
    -addext "keyUsage=digitalSignature" -addext "extendedKeyUsage=codeSigning,1.3.6.1.4.1.2312.16.1.2" \
    -keyout "$TMP/mok.priv" -outform DER -out certs/claudeos-mok.der 2>/dev/null
  (cd "$TMP" && COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null)
  cp "$TMP/cosign.pub" cosign.pub
  NEWKEYS=1
fi

step "4/4  Repository"
if ! gh repo view "$OWNER/claudeos-image" >/dev/null 2>&1; then
  gh repo create claudeos-image --public --description "ClaudeOS system image (Fedora Sway Atomic + labwc + NVIDIA 580)"
fi
git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$OWNER/claudeos-image.git"
if [ "$NEWKEYS" = 1 ]; then
  gh secret set AKMODS_PRIVATE_KEY -R "$OWNER/claudeos-image" < "$TMP/mok.priv"
  gh secret set COSIGN_PRIVATE_KEY -R "$OWNER/claudeos-image" < "$TMP/cosign.key"
  echo "Private keys stored as encrypted repo secrets; local copies are shredded on exit."
fi
git add -A
git -c user.name="$OWNER" -c user.email="$OWNER@users.noreply.github.com" commit -qm "Public keys" || true
git push -u origin main
echo
echo "Done. First build started: https://github.com/$OWNER/claudeos-image/actions"
echo "Tell Claude; it will watch the build and prepare the switch-over."
