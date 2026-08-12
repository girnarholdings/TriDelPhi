#!/usr/bin/env bash
# Prepare a Codespace to run TriDelPhi exactly as CI does.
#
# Deliberately not `pip install tridelphi`: a codespace on this repository
# should exercise THIS checkout, so a change you are about to propose is the
# thing that scans your change.
set -euo pipefail

export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_PYTHON_VERSION_WARNING=1

# Where the wrapped scanners go. install-ladder.sh defaults to a temp directory
# and, outside GitHub Actions, only *prints* "add to PATH" — nothing adds it. A
# codespace set up that way installs five scanners and then reports three of
# them as "not run", which is the confusing half-answer this file exists to
# prevent. So: a durable directory, on PATH, in this shell and in later ones.
TOOLS="$HOME/.local/bin"
mkdir -p "$TOOLS"
export PATH="$TOOLS:$PATH"

echo "Installing TriDelPhi from this checkout…"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev]"

# Level 5 pulls in all five wrapped scanners, checksum-verified by the same
# installer CI uses.
echo "Installing the pinned scanner ladder (checksum-verified)…"
if ! bash scripts/install-ladder.sh 5 "$TOOLS"; then
  echo "WARNING: a scanner failed to install; the core scan still works," >&2
  echo "         but some --level rungs will report as not run." >&2
fi

# Make it stick for every future terminal, without stacking duplicate lines on
# each rebuild.
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -qF 'tridelphi ladder' "$rc" || printf '\n# tridelphi ladder\nexport PATH="%s:$PATH"\n' "$TOOLS" >> "$rc"
done

# Say plainly what is and is not available, rather than letting the first scan
# be where you discover a gap.
echo
missing=0
for tool in gitleaks osv-scanner zizmor scorecard semgrep; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  ready    %s\n' "$tool"
  else
    printf '  MISSING  %s (its rung will report "not run")\n' "$tool"
    missing=$((missing + 1))
  fi
done
[ "$missing" -eq 0 ] && echo "  all five scanners on PATH"

cat <<'BANNER'

  TriDelPhi is ready. Useful starting points:

    tridelphi .                  scan this repository, plain-language report
    tridelphi guard              walk each finding with its exact fix, asking first
    tridelphi . --level 7        the full ladder, as CI runs it
    tridelphi verify .           check pinned actions against the trust-lock
    tridelphi expose ./dist      audit built output for leaked secrets/source
    python -m pytest -q          the test suite

  Everything runs on this machine. Nothing is uploaded.

BANNER
