#!/usr/bin/env bash
# Prepare a Codespace to run TriDelPhi exactly as CI does — and to run every
# optional command too, so nothing has to be installed mid-session.
#
# Deliberately not `pip install tridelphi`: a codespace on this repository
# should exercise THIS checkout, so a change you are about to propose is the
# thing that scans your change.
#
# This script FAILS LOUDLY. An earlier version swallowed errors, and a
# completely failed setup still looked like a working machine: the test suite
# imports tridelphi/ straight from the working directory, so it passed anyway
# and only the skip count quietly moved. A setup that half-works is worse than
# one that stops, because the first thing it costs you is trust in the result.
set -euo pipefail

export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_PYTHON_VERSION_WARNING=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

# Report which step died, not just a bare non-zero exit from postCreateCommand.
failed() {
  local line=$1
  printf '\n\033[1;31m✗ Setup failed (line %s).\033[0m\n' "$line" >&2
  cat >&2 <<'HELP'

  The environment is INCOMPLETE. Do not trust a scan from it — a missing
  scanner reports its rung as "not run", which reads like a clean result.

  To see the full error and retry:
      bash .devcontainer/setup.sh

  If pip could not write its install, that is the usual cause; the message
  above this banner names it.
HELP
  exit 1
}
trap 'failed $LINENO' ERR

# Where the wrapped scanners go. install-ladder.sh defaults to a temp directory
# and, outside GitHub Actions, only *prints* "add to PATH" — nothing adds it. A
# codespace set up that way installs five scanners and then reports three of
# them as "not run".
TOOLS="$HOME/.local/bin"
mkdir -p "$TOOLS"
export PATH="$TOOLS:$PATH"

step "Installing TriDelPhi from this checkout"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev]"

step "Installing the pinned scanner ladder (checksum-verified)"
bash scripts/install-ladder.sh 5 "$TOOLS"

# `privatize` needs javascript-obfuscator, which is npm-only and installed
# on demand everywhere else. Doing it here means the one command that would
# otherwise stop and ask you to install something mid-session just works.
# Integrity-verified against the committed lockfile by the same script.
step "Installing the privatize toolchain (integrity-verified)"
if command -v npm >/dev/null 2>&1; then
  bash scripts/install-privatize.sh "$HOME/.tridelphi-privatize"
  ln -sf "$HOME/.tridelphi-privatize/node_modules/.bin/javascript-obfuscator" "$TOOLS/javascript-obfuscator"
else
  echo "npm is absent, so privatize's obfuscator was skipped." >&2
  echo "Everything else works; run scripts/install-privatize.sh once npm exists." >&2
fi

# Make it stick for every future terminal, without stacking duplicate lines on
# each rebuild.
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -qF 'tridelphi ladder' "$rc" || printf '\n# tridelphi ladder\nexport PATH="%s:$PATH"\n' "$TOOLS" >> "$rc"
done

# Say plainly what is and is not available. A gap belongs here, at setup, not
# in the middle of the first scan you actually cared about.
step "Checking every tool is reachable"
missing=""
for tool in gitleaks osv-scanner zizmor scorecard semgrep javascript-obfuscator; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$tool"
  else
    printf '  \033[31m✗\033[0m %s\n' "$tool"
    missing="$missing $tool"
  fi
done

# The ladder is the reason this container exists; a missing rung is a failure,
# not a note. javascript-obfuscator is the one tolerated absence, because it
# only affects `privatize` and needs npm.
for tool in $missing; do
  if [ "$tool" != "javascript-obfuscator" ]; then
    echo >&2
    echo "Setup finished but$missing did not install. The ladder is why this" >&2
    echo "container exists, so this counts as a failure rather than a note." >&2
    exit 1
  fi
done

cat <<'BANNER'

  TriDelPhi is ready — every command works, nothing left to install.

    tridelphi .                  scan this repository, plain-language report
    tridelphi guard              walk each finding with its exact fix, asking first
    tridelphi . --level 7        the full ladder, as CI runs it
    tridelphi verify .           check pinned actions against the trust-lock
    tridelphi expose ./dist      audit built output for leaked secrets/source
    tridelphi privatize ./dist   obfuscate built JS (opt-in, verifies or reverts)
    python -m pytest -q          the test suite

  Everything runs on this machine. Nothing is uploaded.

BANNER
