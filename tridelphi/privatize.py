"""`tridelphi privatize` — raise the effort of copying your shipped JavaScript.

This is the honest obfuscator. Everything about it is bounded by two facts the
research made non-negotiable:

1. It is **not security**, and it **cannot hide a secret** — anything in a browser
   bundle is readable by anyone who loads the page. So before it touches a file
   it runs the exposure audit's secret check and *refuses* if a key is shipped:
   obfuscation would hide that key from *you*, not from an attacker.
2. Obfuscators can **silently miscompile** (peer-reviewed OOPSLA 2026 "OBsmith"
   found confirmed correctness bugs in the very tool we wrap). So this never
   promises a guarantee: it caps the transform to a safe preset, keeps source
   maps off, skips vendor code, and — this is the whole point — keeps the result
   only if your own smoke check passes against it. Otherwise it reverts to the
   exact original bytes.

Unlike the scanner, this command mutates files and runs your build command, so
it lives entirely outside the offline/deterministic promise, requires interactive
consent, and is unreachable from `--yes` / `fix --apply` / `guard -y`.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TextIO

from .expose import _detect_maps_and_secrets, _Surface

__all__ = ["DirSnapshot", "run_privatize"]

# Directories a web build tends to land in, in the order we'd pick one.
_OUTPUT_DIRS = ("dist", "build", "out", "public")

# The safe-preset flags. Deliberately excludes control-flow flattening, dead-code
# injection, self-defending and debug-protection — the transforms the research
# ties to silent breakage and 17x bundle bloat. Identifier mangling plus a light
# string array is the "Low" end that measured <3% runtime cost.
_SAFE_FLAGS = [
    "--compact", "true",
    "--source-map", "false",
    "--control-flow-flattening", "false",
    "--dead-code-injection", "false",
    "--self-defending", "false",
    "--debug-protection", "false",
    "--disable-console-output", "false",
    "--rename-globals", "false",
    "--string-array", "true",
    "--string-array-threshold", "0.5",
]

_DISCLAIMER = (
    "  privatize raises the effort of copying your shipped JavaScript.\n"
    "  It is NOT security. It cannot hide a secret — anything in browser code is\n"
    "  readable by anyone who loads the page. It can, in rare cases, silently\n"
    "  break your app.\n\n"
    "  TriDelPhi caps it to a safe preset, turns source maps off, skips vendor\n"
    "  code, and keeps the result ONLY if the smoke check you give it passes\n"
    "  against the obfuscated build — otherwise it reverts to your exact files.\n"
    "  That verification is real, but it is not a guarantee.\n"
)

RunCmd = Callable[[str, Path, int], "tuple[bool, str]"]
Obfuscate = Callable[[Path, Path], "tuple[bool, str]"]


@dataclass(frozen=True, slots=True)
class PrivatizeResult:
    status: Literal["done", "reverted", "refused", "unavailable", "declined", "dry-run"]
    detail: str


# ---------------------------------------------------------------------------
# the multi-file snapshot primitive — not apply.py (single-file, no try/finally)
# ---------------------------------------------------------------------------


class DirSnapshot:
    """A copy-on-enter, rollback-or-cleanup-on-exit snapshot of a directory.

    Unlike ``apply.py``'s single-file, in-memory contract, ``privatize`` rewrites
    a whole tree and verifies with a subprocess that can time out or be
    interrupted — so rollback must be crash-safe. On any exception, a
    ``KeyboardInterrupt``, or an uncommitted exit, the original bytes are
    restored; the tempdir is always removed.
    """

    __slots__ = ("_backup", "_committed", "_tmp", "target")

    def __init__(self, target: Path) -> None:
        self.target = target
        self._tmp: Path | None = None
        self._backup: Path | None = None
        self._committed = False

    def __enter__(self) -> DirSnapshot:
        self._tmp = Path(tempfile.mkdtemp(prefix="tridelphi-snap-"))
        # If the copy fails (unreadable tree, disk full), `__exit__` never runs —
        # the `with` block was never entered — so clean the tempdir here rather
        # than leak it. `BaseException` also covers a KeyboardInterrupt mid-copy.
        try:
            self._backup = self._tmp / self.target.name
            shutil.copytree(self.target, self._backup, symlinks=True)
        except BaseException:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None
            self._backup = None
            raise
        return self

    def commit(self) -> None:
        self._committed = True

    def rollback(self) -> None:
        if self._backup is None or not self._backup.exists():
            return
        if self.target.exists():
            shutil.rmtree(self.target)
        shutil.copytree(self._backup, self.target, symlinks=True)

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if (exc_type is not None or not self._committed):
                self.rollback()
        finally:
            if self._tmp is not None and self._tmp.exists():
                shutil.rmtree(self._tmp, ignore_errors=True)
        return False  # never suppress an exception


# ---------------------------------------------------------------------------
# the real transform + verifier (injectable for tests)
# ---------------------------------------------------------------------------


def _find_obfuscator(root: Path) -> list[str] | None:
    """Locate the pinned javascript-obfuscator installed by install-privatize.sh."""
    import os

    dest = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "tridelphi-privatize"
    candidates = [
        root / "node_modules" / ".bin" / "javascript-obfuscator",
        root / ".tridelphi" / "privatize" / "node_modules" / ".bin" / "javascript-obfuscator",
        dest / "node_modules" / ".bin" / "javascript-obfuscator",
    ]
    for c in candidates:
        if c.is_file():
            return [str(c)]
    found = shutil.which("javascript-obfuscator")
    return [found] if found else None


def _default_obfuscate(src: Path, dst: Path) -> tuple[bool, str]:
    argv = _find_obfuscator(src.parent)
    if argv is None:
        return False, (
            "javascript-obfuscator is not installed. Run scripts/install-privatize.sh "
            "(pinned + integrity-checked) first."
        )
    cmd = [*argv, str(src), "--output", str(dst), *_SAFE_FLAGS]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"obfuscator did not run: {exc}"
    if completed.returncode != 0 or not dst.exists():
        return False, (completed.stderr or "obfuscator failed").strip()[:300]
    return True, "obfuscated"


def _default_run_cmd(command: str, cwd: Path, timeout: int) -> tuple[bool, str]:
    """Run the user's OWN verification command, verbatim, through a shell.

    ``command`` is the exact ``--build-cmd`` / ``--smoke-cmd`` string the user
    typed on their own machine, invoked only after explicit interactive consent.
    Real smoke checks routinely need shell operators (``npm run build && node …``,
    a piped health probe) that a split argv could not express, so a shell is
    required by design.

    We spell that as an explicit ``["/bin/sh", "-c", command]`` argv rather than
    ``subprocess.run(command, shell=True)``. The two are equivalent on POSIX and
    the trust model is identical — the command is the user's own consented input,
    never untrusted data spliced into a command line — but the explicit form is
    plainer about deliberately invoking a shell and avoids the ``shell=True``
    string/list footgun if this call is ever refactored. (POSIX ``/bin/sh``; this
    is a dev/CI-runner command, not a Windows path.)
    """
    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", command], cwd=str(cwd), capture_output=True,
            text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"`{command}` did not finish within {timeout}s"
    tail = (completed.stdout or "")[-2000:] + (completed.stderr or "")[-2000:]
    return completed.returncode == 0, tail


# ---------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------


def _resolve_output(root: Path, privatize_out: str | None) -> Path | None:
    if privatize_out:
        p = (root / privatize_out) if not Path(privatize_out).is_absolute() else Path(privatize_out)
        return p if p.is_dir() else None
    for name in _OUTPUT_DIRS:
        cand = root / name
        if cand.is_dir():
            return cand
    return None


# Every critical rule `_detect_maps_and_secrets` can emit that represents a
# *shipped secret* — one obfuscation would hide from the owner, not an attacker.
# Deliberately excludes `source-map-disclosure` (a disclosure, not a key to
# rotate; privatize forces maps off in its own output) and the public-by-design
# notes (`firebase-public-key`, `supabase-anon-key`, which are never critical).
# `supabase-service-role` was the gap: a service_role JWT bypasses Row Level
# Security, yet the old `client-secret`-only filter let it through the interlock.
_INTERLOCK_SECRET_RULES = frozenset({"client-secret", "supabase-service-role"})


def _shipped_secrets(root: Path, target: Path):
    """Category-A secret findings scoped to the obfuscation target — the interlock.

    Every ``.js``/``.map`` under the target counts as shipped output here (the
    target *is* the build directory), so this does not rely on asset-dir naming
    the way the repo-wide audit does. Locations stay repo-relative.
    """
    surface = _Surface()
    for p in sorted(target.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix == ".map":
            surface.maps.append(p)
        elif p.suffix in (".js", ".mjs", ".cjs"):
            surface.bundles.append(p)
    return [f for f in _detect_maps_and_secrets(root, surface)
            if f.severity == "critical" and f.rule in _INTERLOCK_SECRET_RULES]


def run_privatize(
    path: str = ".",
    *,
    build_cmd: str | None = None,
    smoke_cmd: str | None = None,
    privatize_out: str | None = None,
    assume_yes: bool = False,
    input_stream: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    obfuscate: Obfuscate | None = None,
    run_cmd: RunCmd | None = None,
) -> int:
    """Obfuscate a repo's built JavaScript output, verified or reverted.

    Exit codes: 0 done / dry-run / user-declined; 2 refused (secret present,
    non-interactive, no build output) or reverted (verification failed).
    """
    import sys

    out = out or sys.stdout
    err = err or sys.stderr
    obf = obfuscate or _default_obfuscate
    verify = run_cmd or _default_run_cmd
    root = Path(path)

    if not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2

    target = _resolve_output(root, privatize_out)
    if target is None:
        print("tridelphi privatize: no built output found. Build your app first "
              "(e.g. `npm run build`), then point me at the output "
              "(`--privatize-out dist`). privatize never runs on source.", file=err)
        return 2

    print("\n" + _DISCLAIMER, file=out)

    # Consent. --yes / a closed stdin can never satisfy this — the disclaimer is
    # printed and the tool exits without touching a byte.
    if assume_yes:
        print("  Refusing to run non-interactively: privatize can silently break a\n"
              "  shipped app, so it always needs an explicit human 'yes'.\n", file=out)
        return 2
    stream = input_stream or sys.stdin
    print(f"  Target: {target.relative_to(root)}   Proceed? [y/N] ", end="", file=out, flush=True)
    answer = stream.readline().strip().lower()
    if answer[:1] != "y":
        print("  Declined — nothing was changed.\n", file=out)
        return 0

    # Secret interlock — the load-bearing honesty check.
    secrets = _shipped_secrets(root, target)
    if secrets:
        print("\n  ⛔ Refusing: your build ships what looks like a live secret.\n"
              "     Obfuscation would hide it from you, not from an attacker who can\n"
              "     still read it in the browser. Rotate it and move it server-side\n"
              "     first, then run privatize again.\n", file=err)
        for f in secrets:
            print(f"       · {f.where} — {f.message.split('.')[0]}.", file=err)
        return 2

    tmp_out = target.parent / (target.name + ".tridelphi-tmp")
    if tmp_out.exists():
        shutil.rmtree(tmp_out)

    ok, detail = obf(target, tmp_out)
    if not ok:
        if tmp_out.exists():
            shutil.rmtree(tmp_out, ignore_errors=True)
        print(f"\n  Could not obfuscate: {detail}\n", file=err)
        return 2

    # No smoke check → dry-run. We never replace a working build with output we
    # could not verify; we leave the obfuscated copy beside it for the user.
    if not smoke_cmd:
        print(f"\n  ✓ Wrote an obfuscated copy to {tmp_out.relative_to(root)} — I did NOT\n"
              "    touch your live output. Test that copy, and if it works, swap it in\n"
              "    yourself. Pass --smoke-cmd next time and I'll verify and swap for you.\n",
              file=out)
        return 0

    # Verified swap: back up the original, put the obfuscated output in place,
    # run the user's checks, and keep it only if they pass.
    with DirSnapshot(target) as snap:
        shutil.rmtree(target)
        tmp_out.replace(target)
        for label, cmd in (("build", build_cmd), ("smoke", smoke_cmd)):
            if not cmd:
                continue
            passed, output = verify(cmd, root, 900)
            if not passed:
                print(f"\n  ✗ The {label} check failed on the obfuscated build — reverting.\n"
                      f"    Your files are back exactly as they were.\n"
                      f"    {label}: {output.strip()[-300:]}\n", file=err)
                return 2  # DirSnapshot rolls back on the uncommitted exit
        snap.commit()

    print("\n  ✓ Obfuscated and verified against your checks. Your build output is now\n"
          "    harder to read. This is not a guarantee — obfuscators can miscompile;\n"
          "    keep your source in version control and test before you ship.\n", file=out)
    return 0
