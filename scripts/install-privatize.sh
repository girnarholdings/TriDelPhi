#!/usr/bin/env bash
# Install the pinned obfuscator for `tridelphi privatize`.
#
#   install-privatize.sh [dest-dir]
#
# Installs javascript-obfuscator (BSD-2-Clause) at the exact version pinned in
# .tridelphi/privatize/package.json, verified against the committed
# package-lock.json via `npm ci` — every artifact is checked against the
# sha512 `integrity` in the lockfile, and a mismatch is a hard failure.
#
# `--ignore-scripts` blocks any postinstall hook: an obfuscator we run over a
# user's build must not itself execute third-party install scripts. This is a
# separate installer from the ladder on purpose — privatize is not a scanner
# rung; it is an opt-in, mutating command, so it is never installed by a scan.
#
# Node.js + npm are required (the tool is npm-only). If they are absent, or the
# install fails, `tridelphi privatize` degrades gracefully with an install hint
# rather than doing anything unsafe.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${HERE}/../.tridelphi/privatize"
DEST="${1:-${RUNNER_TEMP:-/tmp}/tridelphi-privatize}"

if ! command -v npm >/dev/null 2>&1; then
  echo "install-privatize: npm not found — javascript-obfuscator needs Node.js/npm." >&2
  exit 1
fi
if [ ! -f "${SRC}/package-lock.json" ]; then
  echo "install-privatize: pinned lockfile missing at ${SRC}." >&2
  exit 1
fi

mkdir -p "${DEST}"
cp "${SRC}/package.json" "${SRC}/package-lock.json" "${DEST}/"
cd "${DEST}"

# `npm ci` installs exactly the locked tree and verifies every integrity hash.
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error

BIN="${DEST}/node_modules/.bin/javascript-obfuscator"
if [ ! -x "${BIN}" ]; then
  echo "install-privatize: install finished but ${BIN} is missing." >&2
  exit 1
fi
VER="$(cd "${DEST}" && node -p "require('javascript-obfuscator/package.json').version")"
echo "installed javascript-obfuscator v${VER} (integrity-verified) at ${DEST}"
