#!/usr/bin/env bash
# Install the pinned open-source scanners for the TriDelPhi hardening ladder.
#
#   install-ladder.sh <level> [dest-dir]
#
# Level 1 installs gitleaks, 2 adds osv-scanner, 3 adds zizmor. Every binary is
# pinned to an exact version and verified against a SHA-256 digest taken from
# the project's own release artifacts:
#
#   * gitleaks  — digest from the official gitleaks_8.28.0_checksums.txt
#   * osv-scanner — digest from the release's SLSA provenance attestation
#     (multiple.intoto.jsonl subject for osv-scanner_linux_amd64)
#   * zizmor — version-pinned from PyPI (binary wheels per platform)
#
# A checksum mismatch is a hard failure on purpose: it means the artifact is
# not the one that was reviewed, and nothing after that point can be trusted.
#
# The prebuilt binaries are linux/x86_64 (GitHub-hosted ubuntu runners). On any
# other platform those rungs are skipped with a notice — TriDelPhi itself
# degrades gracefully when a scanner is absent.

set -euo pipefail

LEVEL="${1:-3}"
DEST="${2:-${RUNNER_TEMP:-/tmp}/tridelphi-tools}"

GITLEAKS_VERSION=8.28.0
GITLEAKS_SHA256=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
OSV_SCANNER_VERSION=2.2.4
OSV_SCANNER_SHA256=7702cd1e5d9f5059dd9570f4ad967f27d3c5f5391b371ec937b384c238177f55
ZIZMOR_VERSION=1.29.0

mkdir -p "$DEST"

linux_amd64() { [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; }

fetch_verified() { # url sha256 outfile
  local url="$1" sha="$2" out="$3"
  curl -sSL --fail --retry 3 -o "$out" "$url"
  echo "${sha}  ${out}" | sha256sum -c - >/dev/null
}

if [ "$LEVEL" -ge 1 ]; then
  if linux_amd64; then
    fetch_verified \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      "$GITLEAKS_SHA256" "$DEST/gitleaks.tgz"
    tar -xzf "$DEST/gitleaks.tgz" -C "$DEST" gitleaks
    rm "$DEST/gitleaks.tgz"
    echo "installed gitleaks v${GITLEAKS_VERSION} (verified)"
  else
    echo "notice: prebuilt gitleaks is linux/x86_64 only; L1 will be skipped on this runner" >&2
  fi
fi

if [ "$LEVEL" -ge 2 ]; then
  if linux_amd64; then
    fetch_verified \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
      "$OSV_SCANNER_SHA256" "$DEST/osv-scanner"
    chmod +x "$DEST/osv-scanner"
    echo "installed osv-scanner v${OSV_SCANNER_VERSION} (verified)"
  else
    echo "notice: prebuilt osv-scanner is linux/x86_64 only; L2 will be skipped on this runner" >&2
  fi
fi

if [ "$LEVEL" -ge 3 ]; then
  python3 -m pip install --quiet "zizmor==${ZIZMOR_VERSION}"
  echo "installed zizmor v${ZIZMOR_VERSION}"
fi

# Make the tools visible to later workflow steps when running under Actions.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$DEST" >> "$GITHUB_PATH"
else
  echo "add to PATH: $DEST"
fi
