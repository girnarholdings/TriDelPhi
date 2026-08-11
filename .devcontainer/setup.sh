#!/usr/bin/env bash
# Prepare a Codespace to run TriDelPhi exactly as CI does.
#
# Deliberately not `pip install tridelphi`: a codespace on this repository
# should exercise THIS checkout, so a change you are about to propose is the
# thing that scans your change.
set -euo pipefail

export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_PYTHON_VERSION_WARNING=1

echo "Installing TriDelPhi from this checkout…"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev]"

# Level 5 pulls in all five wrapped scanners, checksum-verified by the same
# installer CI uses. Without them `guard` reports most rungs as "not run", which
# is the confusing half-answer this setup exists to avoid.
echo "Installing the pinned scanner ladder (checksum-verified)…"
if bash scripts/install-ladder.sh 5; then
  echo "Ladder ready."
else
  echo "WARNING: a scanner failed to install; the core scan still works," >&2
  echo "         but --level rungs above 0 will report as not run." >&2
fi

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
