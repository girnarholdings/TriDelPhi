"""`tridelphi privatize` — the honest, consent-gated obfuscator.

The load-bearing invariants, all tested here with an injected transform so the
suite stays hermetic (the real javascript-obfuscator is exercised in the live
tier at the bottom):

* it **refuses** to run under ``--yes`` / a closed stdin — a mutating command
  that can silently break an app always needs a human "yes";
* the **secret interlock** refuses when the build ships a key-shaped string,
  because obfuscation would hide it from *you*, not an attacker;
* with no smoke check it is a **dry-run** — it writes a copy and never touches
  the live output;
* a verified swap keeps the obfuscated build **only** if the check passes, and
  a failing check reverts to the **exact original bytes**;
* ``DirSnapshot`` restores byte-for-byte on any uncommitted or exceptional exit
  and always removes its tempdir.
"""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from tridelphi.privatize import DirSnapshot, run_privatize


def _app(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "app"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def _marker_obfuscate(src: Path, dst: Path) -> tuple[bool, str]:
    """A stand-in transform: copy the tree and append a marker to each .js."""
    shutil.copytree(src, dst)
    for p in dst.rglob("*.js"):
        p.write_text(p.read_text(encoding="utf-8") + "\n/*obf*/", encoding="utf-8")
    return True, "obfuscated"


def _pass(cmd: str, cwd: Path, timeout: int) -> tuple[bool, str]:
    return True, "ok"


def _fail(cmd: str, cwd: Path, timeout: int) -> tuple[bool, str]:
    return False, "smoke boot failed"


# ---------------------------------------------------------------------------
# DirSnapshot — the crash-safe rollback primitive
# ---------------------------------------------------------------------------


def test_dirsnapshot_reverts_on_uncommitted_exit(tmp_path):
    target = tmp_path / "dist"
    target.mkdir()
    (target / "a.js").write_text("original", encoding="utf-8")
    with DirSnapshot(target):
        (target / "a.js").write_text("mutated", encoding="utf-8")
        (target / "new.js").write_text("added", encoding="utf-8")
        # no commit()
    assert (target / "a.js").read_text() == "original"
    assert not (target / "new.js").exists()


def test_dirsnapshot_keeps_on_commit(tmp_path):
    target = tmp_path / "dist"
    target.mkdir()
    (target / "a.js").write_text("original", encoding="utf-8")
    with DirSnapshot(target) as snap:
        (target / "a.js").write_text("mutated", encoding="utf-8")
        snap.commit()
    assert (target / "a.js").read_text() == "mutated"


def test_dirsnapshot_reverts_on_exception_and_reraises(tmp_path):
    target = tmp_path / "dist"
    target.mkdir()
    (target / "a.js").write_text("original", encoding="utf-8")
    tmp_seen: list[Path] = []
    with pytest.raises(RuntimeError), DirSnapshot(target) as snap:
        tmp_seen.append(snap._tmp)
        (target / "a.js").write_text("mutated", encoding="utf-8")
        raise RuntimeError("boom")
    assert (target / "a.js").read_text() == "original", "exception must roll back"
    assert tmp_seen[0] is not None and not tmp_seen[0].exists(), "tempdir must be removed"


def test_dirsnapshot_cleans_tempdir_when_enter_copy_fails(tmp_path, monkeypatch):
    """If the copy inside `__enter__` raises, the `with` block is never entered
    and `__exit__` never runs — so `__enter__` must clean its own mkdtemp or it
    leaks a tempdir on every failed snapshot."""
    import tridelphi.privatize as pv

    target = tmp_path / "dist"
    target.mkdir()
    (target / "a.js").write_text("original", encoding="utf-8")

    created: list[str] = []
    real_mkdtemp = pv.tempfile.mkdtemp

    def spy_mkdtemp(*a, **k):
        d = real_mkdtemp(*a, **k)
        created.append(d)
        return d

    monkeypatch.setattr(pv.tempfile, "mkdtemp", spy_mkdtemp)
    monkeypatch.setattr(pv.shutil, "copytree", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError), DirSnapshot(target):
        pass  # unreachable — __enter__ raises

    assert created, "mkdtemp should have been called"
    assert not Path(created[0]).exists(), "the tempdir must be removed on enter failure"


# ---------------------------------------------------------------------------
# consent gate — never mutate without an explicit human yes
# ---------------------------------------------------------------------------


def test_yes_flag_is_refused_without_touching_a_byte(tmp_path):
    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    before = (app / "dist/main.js").read_text()
    out = io.StringIO()
    code = run_privatize(str(app), assume_yes=True, out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 2
    assert "non-interactively" in out.getvalue()
    assert (app / "dist/main.js").read_text() == before


def test_declined_answer_changes_nothing(tmp_path):
    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    before = (app / "dist/main.js").read_text()
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO("n\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 0
    assert "Declined" in out.getvalue()
    assert (app / "dist/main.js").read_text() == before


def test_closed_stdin_declines(tmp_path):
    """EOF (empty readline) is not a yes — it declines, untouched."""
    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO(""), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 0
    assert (app / "dist/main.js").read_text() == "console.log(1)"


# ---------------------------------------------------------------------------
# secret interlock — the honesty check
# ---------------------------------------------------------------------------


def test_shipped_secret_refuses_obfuscation(tmp_path):
    app = _app(tmp_path, {"dist/main.js": 'var k="AKIAIOSFODNN7EXAMPLE";'})
    before = (app / "dist/main.js").read_text()
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 2
    assert "Refusing" in out.getvalue()
    # It never ran the transform, so the file is byte-identical.
    assert (app / "dist/main.js").read_text() == before
    # And the full secret is never echoed in the refusal message.
    assert "AKIAIOSFODNN7EXAMPLE" not in out.getvalue()


def _supabase_service_role_jwt() -> str:
    """A structurally valid Supabase service_role key (a JWT whose payload sets
    role=service_role). The signature is a placeholder — the interlock reads the
    role claim, not the signature."""
    import base64
    import json

    def seg(obj) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = seg({"alg": "HS256", "typ": "JWT"})
    payload = seg({"role": "service_role", "iss": "supabase", "ref": "abcdefgh"})
    return f"{header}.{payload}.c2lnbmF0dXJlX3BsYWNlaG9sZGVyX3ZhbHVl"


def test_service_role_key_refuses_obfuscation(tmp_path):
    """Regression: the interlock filtered on `rule == 'client-secret'` only, so a
    Supabase service_role key — which bypasses Row Level Security and must never
    ship — sailed straight through and got obfuscated. It must refuse."""
    jwt = _supabase_service_role_jwt()
    app = _app(tmp_path, {"dist/main.js": f'var supabase="{jwt}";'})
    before = (app / "dist/main.js").read_text()
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 2
    assert "Refusing" in out.getvalue()
    assert (app / "dist/main.js").read_text() == before
    assert jwt not in out.getvalue()


# ---------------------------------------------------------------------------
# dry-run vs verified swap vs rollback
# ---------------------------------------------------------------------------


def test_no_smoke_cmd_is_a_dry_run(tmp_path):
    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 0
    assert "did NOT" in out.getvalue()
    # Live output untouched; the obfuscated copy sits beside it.
    assert (app / "dist/main.js").read_text() == "console.log(1)"
    assert (app / "dist.tridelphi-tmp/main.js").read_text().endswith("/*obf*/")


def test_verified_swap_keeps_obfuscated_output(tmp_path):
    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    out = io.StringIO()
    code = run_privatize(str(app), smoke_cmd="true",
                         input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 0
    assert (app / "dist/main.js").read_text().endswith("/*obf*/"), "obfuscated output swapped in"
    assert not (app / "dist.tridelphi-tmp").exists(), "tmp staging removed"


def test_failing_smoke_reverts_to_exact_bytes(tmp_path):
    app = _app(tmp_path, {"dist/main.js": "console.log(1)", "dist/vendor.js": "x=2"})
    originals = {p: p.read_bytes() for p in (app / "dist").rglob("*")}
    out = io.StringIO()
    code = run_privatize(str(app), smoke_cmd="false",
                         input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_fail)
    assert code == 2
    assert "reverting" in out.getvalue()
    for p, data in originals.items():
        assert p.read_bytes() == data, f"{p} must be restored byte-for-byte"
    assert not (app / "dist.tridelphi-tmp").exists()


# ---------------------------------------------------------------------------
# refusals: no build output, not a directory
# ---------------------------------------------------------------------------


def test_source_only_repo_is_refused(tmp_path):
    app = _app(tmp_path, {"src/index.ts": "export const x = 1;\n"})
    out = io.StringIO()
    code = run_privatize(str(app), input_stream=io.StringIO("y\n"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 2
    assert "no built output" in out.getvalue()


def test_missing_path_is_refused(tmp_path):
    out = io.StringIO()
    code = run_privatize(str(tmp_path / "nope"), out=out, err=out,
                         obfuscate=_marker_obfuscate, run_cmd=_pass)
    assert code == 2


# ---------------------------------------------------------------------------
# privatize is unreachable from the automated / batch paths
# ---------------------------------------------------------------------------


def test_privatize_unreachable_from_cli_yes(tmp_path, monkeypatch):
    """`tridelphi privatize --yes` must refuse — the batch spelling can't obfuscate."""
    from tridelphi import cli

    app = _app(tmp_path, {"dist/main.js": "console.log(1)"})
    before = (app / "dist/main.js").read_text()
    # Guard against any accidental real subprocess (obfuscator/build) from this path.
    monkeypatch.setattr("tridelphi.privatize._default_obfuscate",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not obfuscate")))
    code = cli.main(["privatize", str(app), "--yes"])
    assert code == 2
    assert (app / "dist/main.js").read_text() == before


def test_obfuscator_in_a_world_writable_dir_is_rejected(tmp_path):
    """privatize executes whatever `_find_obfuscator` returns, so a binary in a
    group/world-writable directory — where anyone could replace it — must be
    refused even though the file exists and is executable."""
    import os

    from tridelphi.privatize import _find_obfuscator, _safe_from_tampering

    safe_dir = tmp_path / "safe" / "node_modules" / ".bin"
    safe_dir.mkdir(parents=True)
    safe_bin = safe_dir / "javascript-obfuscator"
    safe_bin.write_text("#!/bin/sh\n")
    safe_bin.chmod(0o755)
    assert _safe_from_tampering(safe_bin)
    assert _find_obfuscator(tmp_path / "safe") == [str(safe_bin)]

    # Same binary, but its directory is world-writable → tamperable → rejected.
    os.chmod(safe_dir, 0o757)
    assert not _safe_from_tampering(safe_bin)
    # ...and now discovery falls through to whatever is (safely) on PATH, or None.
    got = _find_obfuscator(tmp_path / "safe")
    assert got is None or got != [str(safe_bin)]


# ---------------------------------------------------------------------------
# live tier — the real javascript-obfuscator, if installed
# ---------------------------------------------------------------------------


def _real_obfuscator() -> str | None:
    import os

    dest = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "tridelphi-privatize"
    bin_ = dest / "node_modules" / ".bin" / "javascript-obfuscator"
    if bin_.is_file():
        return str(bin_)
    return shutil.which("javascript-obfuscator")


@pytest.mark.skipif(_real_obfuscator() is None, reason="javascript-obfuscator not installed")
def test_real_obfuscator_verified_swap_preserves_behaviour(tmp_path):
    app = _app(tmp_path, {
        "dist/main.js": (
            'function greet(name){const m="Hello, "+name+"!";console.log(m);return m;}\n'
            'greet("world");\n'
        ),
        "smoke.sh": '#!/usr/bin/env bash\n[ "$(node dist/main.js)" = "Hello, world!" ]\n',
    })
    (app / "smoke.sh").chmod(0o755)
    out = io.StringIO()
    code = run_privatize(str(app), smoke_cmd="./smoke.sh",
                         input_stream=io.StringIO("y\n"), out=out, err=out)
    assert code == 0, out.getvalue()
    body = (app / "dist/main.js").read_text(encoding="utf-8")
    assert "greet" not in body or "_0x" in body, "identifiers should be mangled"
    # Behaviour preserved: the smoke check passed, so it still prints the greeting.


@pytest.mark.skipif(_real_obfuscator() is None, reason="javascript-obfuscator not installed")
def test_real_obfuscator_failing_smoke_rolls_back(tmp_path):
    original = 'console.log("Hello, world!");\n'
    app = _app(tmp_path, {
        "dist/main.js": original,
        # a smoke check that always fails → must revert to the exact original bytes
        "smoke.sh": "#!/usr/bin/env bash\nexit 1\n",
    })
    (app / "smoke.sh").chmod(0o755)
    out = io.StringIO()
    code = run_privatize(str(app), smoke_cmd="./smoke.sh",
                         input_stream=io.StringIO("y\n"), out=out, err=out)
    assert code == 2
    assert (app / "dist/main.js").read_text(encoding="utf-8") == original
