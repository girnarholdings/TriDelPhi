#!/usr/bin/env bash
# Cloud Agent install: make THIS checkout fully usable, exactly as CI runs it.
#
# Mirrors .devcontainer/setup.sh (the Codespaces path) but targets the Cloud
# Agent VM: the user is `ubuntu`, only `python3` exists, and pip installs into
# ~/.local. Everything lands under $HOME so it is captured by an environment
# snapshot and survives into a fresh pod without being reinstalled per boot.
#
# It FAILS LOUDLY. A half-installed ladder is worse than none: a missing
# scanner reports its rung as "not run", which reads like a clean result.
set -euo pipefail

export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_PYTHON_VERSION_WARNING=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

# User-scoped bin: pip console scripts and the wrapped scanners both land here.
# It is already on the default login PATH; the guarded append below keeps that
# true on a plain image too, without stacking duplicate lines on re-runs.
TOOLS="$HOME/.local/bin"
mkdir -p "$TOOLS"
export PATH="$TOOLS:$PATH"

step "Installing TriDelPhi from this checkout (editable, with dev extras)"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -e ".[dev]"

step "Installing the pinned scanner ladder (checksum-verified)"
bash scripts/install-ladder.sh 5 "$TOOLS"

# `privatize` needs javascript-obfuscator (npm-only). Installing it here means
# the one mutating command that would otherwise stop to install something
# mid-session just works. Integrity-verified against the committed lockfile.
step "Installing the privatize toolchain (integrity-verified)"
if command -v npm >/dev/null 2>&1; then
  bash scripts/install-privatize.sh "$HOME/.tridelphi-privatize"
  ln -sf "$HOME/.tridelphi-privatize/node_modules/.bin/javascript-obfuscator" "$TOOLS/javascript-obfuscator"
else
  echo "npm is absent, so privatize's obfuscator was skipped." >&2
  echo "Everything else works; run scripts/install-privatize.sh once npm exists." >&2
fi

# Persist PATH for every future login shell, idempotently.
for rc in "$HOME/.bashrc" "$HOME/.profile"; do
  [ -f "$rc" ] || touch "$rc"
  grep -qF 'tridelphi ladder' "$rc" || printf '\n# tridelphi ladder\nexport PATH="%s:$PATH"\n' "$TOOLS" >> "$rc"
done

# Say plainly what is and is not available — a gap belongs here, at install,
# not in the middle of the first scan you actually cared about.
step "Checking every tool is reachable"
missing=""
for tool in gitleaks osv-scanner zizmor scorecard semgrep javascript-obfuscator tridelphi; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$tool"
  else
    printf '  \033[31m✗\033[0m %s\n' "$tool"
    missing="$missing $tool"
  fi
done

# The ladder is the reason this setup exists; a missing rung is a failure, not
# a note. javascript-obfuscator is the one tolerated absence (needs npm, only
# affects the opt-in `privatize`).
for tool in $missing; do
  if [ "$tool" != "javascript-obfuscator" ]; then
    echo >&2
    echo "Install finished but$missing did not install. The ladder is why this" >&2
    echo "setup exists, so this counts as a failure rather than a note." >&2
    exit 1
  fi
done

cat <<'BANNER'

  TriDelPhi is ready — every command works, nothing left to install.

    tridelphi .                  scan this repository, plain-language report
    tridelphi . --level 7        the full ladder, as CI runs it
    tridelphi verify .           check pinned actions against the trust-lock
    python3 -m pytest -q         the test suite
    (cd bot && npm test)         the Cloudflare Worker tests

  Everything runs on this machine. Nothing is uploaded.

BANNER
