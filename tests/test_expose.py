"""The exposure audit — `tridelphi expose`.

Native detectors (source maps, client secrets, DB config, minification, committed
data) are pure file reads: deterministic, offline, no subprocess. The code-pattern
rung is semgrep with a local ruleset and is exercised in the live tier. The load-
bearing invariants: high-confidence findings gate (critical), heuristics don't,
the audit never claims to reach a live server, and it never crashes on bad input.
"""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest

from tridelphi.expose import analyze_exposure
from tridelphi.expose_cmd import run_expose


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "app"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def _native(root: Path):
    """Analyze with the semgrep rung off — the pure-native, hermetic path."""
    return analyze_exposure(root, tool_version="0.1.0", run_semgrep=False)


def _cats(result) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        out.setdefault(f.category, []).append(f)
    return out


# ---------------------------------------------------------------------------
# category A — shipped source maps + client secrets
# ---------------------------------------------------------------------------


def test_source_map_with_sources_content_is_critical(tmp_path):
    root = _repo(tmp_path, {
        "dist/app.js.map": json.dumps({"version": 3, "sourcesContent": ["const s = 1; // logic"]}),
    })
    result = _native(root)
    crit = [f for f in result.findings if f.severity == "critical"]
    assert crit and crit[0].category == "A"
    assert "source" in crit[0].message.lower()
    assert result.gating()


def test_bare_source_map_is_only_a_warning(tmp_path):
    root = _repo(tmp_path, {"dist/app.js.map": json.dumps({"version": 3, "mappings": "AAAA"})})
    result = _native(root)
    assert not result.gating()
    assert any(f.category == "A" and f.severity == "warning" for f in result.findings)


def test_client_secret_in_bundle_is_critical(tmp_path):
    root = _repo(tmp_path, {"dist/main.js": 'var k="AKIAIOSFODNN7EXAMPLE";'})
    result = _native(root)
    crit = [f for f in result.findings if f.severity == "critical" and f.category == "A"]
    assert crit, "an AWS key shipped in a bundle must be critical"
    # The full secret body must never be printed (the public AKIA prefix is fine).
    assert "AKIAIOSFODNN7EXAMPLE" not in crit[0].message


def test_secret_only_flagged_inside_asset_dirs(tmp_path):
    # A key in source (not a shipped bundle) is gitleaks' job, not this detector's.
    root = _repo(tmp_path, {"src/config.js": 'var k="AKIAIOSFODNN7EXAMPLE";'})
    result = _native(root)
    assert not [f for f in result.findings if f.category == "A"]


# ---------------------------------------------------------------------------
# category D — database misconfig
# ---------------------------------------------------------------------------

_PUBLIC_DEFAULT = """\
services:
  db:
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_PASSWORD: postgres
"""
_LOCAL_STRONG = """\
services:
  db:
    image: postgres:16
    ports: ["127.0.0.1:5432:5432"]
    environment:
      POSTGRES_PASSWORD: t9x!Qm2z_Vh7
"""


def test_public_db_with_default_password_is_critical(tmp_path):
    root = _repo(tmp_path, {"docker-compose.yml": _PUBLIC_DEFAULT})
    result = _native(root)
    crit = [f for f in result.findings if f.severity == "critical" and f.category == "D"]
    assert crit, "public bind + default password must be critical"
    assert crit[0].where.startswith("docker-compose.yml")


def test_local_bind_strong_password_is_clean(tmp_path):
    root = _repo(tmp_path, {"docker-compose.yml": _LOCAL_STRONG})
    result = _native(root)
    assert not [f for f in result.findings if f.category == "D"], (
        "a 127.0.0.1 bind with a strong password is the correct pattern and must not flag"
    )


def test_env_db_url_credential_is_warning(tmp_path):
    root = _repo(tmp_path, {".env": "DATABASE_URL=postgres://admin:hunter2@db.example.com/app\n"})
    result = _native(root)
    d = [f for f in result.findings if f.category == "D"]
    assert d and all(f.severity == "warning" for f in d)


def test_env_example_is_ignored(tmp_path):
    root = _repo(tmp_path, {".env.example": "DATABASE_URL=postgres://user:pass@host/db\n"})
    result = _native(root)
    assert not result.findings, "template env files must not be scanned"


# ---------------------------------------------------------------------------
# category C (native) + E (minification)
# ---------------------------------------------------------------------------


def test_committed_data_with_sensitive_column_is_warning(tmp_path):
    root = _repo(tmp_path, {"seed_users.json": '[{"email":"a@b.co","password":"plaintext"}]'})
    result = _native(root)
    assert any(f.category == "C" and f.severity == "warning" for f in result.findings)


def test_minified_bundle_reports_already_protected(tmp_path):
    minified = "var a=1;" * 400  # long single line, no whitespace
    root = _repo(tmp_path, {"dist/app.js": minified})
    result = _native(root)
    notes = [f for f in result.findings if f.category == "E"]
    assert notes and notes[0].rule == "minified"


def test_unminified_bundle_suggests_minifier(tmp_path):
    pretty = "\n".join(f"  const x{i} = {i};" for i in range(50))
    root = _repo(tmp_path, {"dist/app.js": pretty})
    result = _native(root)
    notes = [f for f in result.findings if f.category == "E"]
    assert notes and notes[0].rule == "not-minified"


# ---------------------------------------------------------------------------
# invariants: offline, deterministic, contained, honest
# ---------------------------------------------------------------------------


def test_native_path_spawns_no_subprocess(tmp_path, monkeypatch):
    """The native audit must be pure file reads — no subprocess, ever."""
    import subprocess

    def _boom(*a, **k):
        raise AssertionError("expose native path spawned a subprocess")

    monkeypatch.setattr(subprocess, "run", _boom)
    root = _repo(tmp_path, {"docker-compose.yml": _PUBLIC_DEFAULT})
    result = _native(root)  # run_semgrep=False → no subprocess
    assert result.gating()


def test_audit_is_deterministic(tmp_path):
    root = _repo(tmp_path, {
        "dist/app.js.map": json.dumps({"version": 3, "sourcesContent": ["x"]}),
        "docker-compose.yml": _PUBLIC_DEFAULT,
        ".env": "DATABASE_URL=postgres://u:p@h/d\n",
    })
    a = json.dumps(_native(root).sarif, sort_keys=True)
    b = json.dumps(_native(root).sarif, sort_keys=True)
    assert a == b, "two audits of the same tree must be byte-identical"


def test_native_sarif_passes_the_shape_gate(tmp_path):
    from tridelphi.orchestrate import sarif_shape_error

    root = _repo(tmp_path, {"docker-compose.yml": _PUBLIC_DEFAULT})
    assert sarif_shape_error(_native(root).sarif) is None


def test_malformed_files_never_crash(tmp_path):
    root = _repo(tmp_path, {
        "dist/app.js.map": "{not json",
        "docker-compose.yml": "this: is: not: valid: yaml: [",
        ".env": "\x00\x01 garbage \xff",
    })
    result = _native(root)  # must not raise
    assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# the command: exit codes + rendering
# ---------------------------------------------------------------------------


def test_run_expose_criticals_exit_one(tmp_path, monkeypatch):
    # keep it hermetic: no real semgrep
    monkeypatch.setattr("tridelphi.expose.run_tool",
                        lambda *a, **k: _skip_run())
    root = _repo(tmp_path, {"docker-compose.yml": _PUBLIC_DEFAULT})
    out = io.StringIO()
    code = run_expose(str(root), out=out)
    assert code == 1
    text = " ".join(out.getvalue().split())  # normalize wrap boundaries
    assert "NOT YET SAFE" in text
    assert "can't reach a running database" in text  # the honest-scope line, always present


def test_run_expose_clean_exits_zero(tmp_path, monkeypatch):
    monkeypatch.setattr("tridelphi.expose.run_tool", lambda *a, **k: _skip_run())
    root = _repo(tmp_path, {"src/app.ts": "export const x = 1;\n"})
    out = io.StringIO()
    code = run_expose(str(root), out=out)
    assert code == 0
    assert "looks exposed" in out.getvalue()


def test_run_expose_markdown_is_inbox_ready(tmp_path, monkeypatch):
    monkeypatch.setattr("tridelphi.expose.run_tool", lambda *a, **k: _skip_run())
    root = _repo(tmp_path, {"dist/main.js": 'var k="AKIAIOSFODNN7EXAMPLE";'})
    out = io.StringIO()
    run_expose(str(root), fmt="markdown", out=out)
    md = out.getvalue()
    assert md.startswith("### 🔺 TriDelPhi exposure audit")
    assert "| Check | Result |" in md
    assert "```" not in md, "no monospace dumps in the comment/email"
    assert "verify network-facing config" in md  # honest scope survives


def _skip_run():
    from tridelphi.ladder import SEMGREP_EXPOSURE, ExternalRun
    from tridelphi.model import Diagnostic

    return ExternalRun(SEMGREP_EXPOSURE, diagnostic=Diagnostic(path="", message="semgrep not installed"))


# ---------------------------------------------------------------------------
# live tier — the semgrep code-pattern rung
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_weak_hash_and_localstorage_live(tmp_path):
    root = _repo(tmp_path, {
        "auth.py": "import hashlib\ndef s(password): return hashlib.md5(password.encode()).hexdigest()\n",
        "session.js": 'localStorage.setItem("authToken", token);\n',
    })
    result = analyze_exposure(root, tool_version="0.1.0", run_semgrep=True)
    assert result.semgrep_ran
    cats = _cats(result)
    assert any(f.rule and "hash" in f.rule for f in cats.get("B", [])), "weak hash → B"
    assert any("storage" in f.rule or "token" in f.rule for f in cats.get("C", [])), "localStorage → C"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_jwt_and_tls_disabled_live(tmp_path):
    root = _repo(tmp_path, {
        "auth.py": "import jwt\ndef v(t): return jwt.decode(t, key, algorithms=['none'])\n",
        "net.py": "import requests\ndef g(u): return requests.get(u, verify=False)\n",
    })
    result = analyze_exposure(root, tool_version="0.1.0", run_semgrep=True)
    assert result.semgrep_ran
    c_rules = [f.rule for f in _cats(result).get("C", [])]
    assert any("jwt" in r for r in c_rules), "JWT verify disabled → C"
    assert any("tls" in r for r in c_rules), "TLS verify disabled → C"


# ---------------------------------------------------------------------------
# extended secret shapes (category A) + Firebase precision
# ---------------------------------------------------------------------------


def test_openai_key_in_bundle_is_critical_and_masked(tmp_path):
    key = "sk-proj-" + "a" * 48
    root = _repo(tmp_path, {"dist/app.js": f'const c="{key}";'})
    result = _native(root)
    crit = [f for f in result.findings if f.category == "A" and f.severity == "critical"]
    assert crit, "an OpenAI key shipped in a bundle must be critical"
    assert all(key not in f.message for f in crit), "the key body must be masked"


def test_anthropic_key_not_double_reported_as_openai(tmp_path):
    root = _repo(tmp_path, {"dist/app.js": 'const c="sk-ant-' + "a" * 40 + '";'})
    result = _native(root)
    crit = [f for f in result.findings if f.rule == "client-secret" and f.severity == "critical"]
    assert len(crit) == 1, "the Anthropic key must produce exactly one finding, not also an OpenAI one"
    assert "Anthropic" in crit[0].message


def test_firebase_web_key_is_a_note_not_critical(tmp_path):
    body = 'const firebaseConfig={apiKey:"AIza' + "b" * 35 + '",authDomain:"x.firebaseapp.com"};'
    root = _repo(tmp_path, {"dist/app.js": body})
    result = _native(root)
    assert not result.gating(), "a Firebase web apiKey is public by design — must not gate"
    notes = [f for f in result.findings if f.rule == "firebase-public-key"]
    assert notes and notes[0].severity == "note"
    assert "Security Rules" in notes[0].fix


# ---------------------------------------------------------------------------
# category F — committed credentials / cloud config
# ---------------------------------------------------------------------------


def test_committed_private_key_pem_is_critical(tmp_path):
    root = _repo(tmp_path, {
        "certs/server.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n",
    })
    result = _native(root)
    crit = [f for f in result.findings if f.category == "F" and f.severity == "critical"]
    assert crit and crit[0].rule == "committed-private-key"


def test_public_certificate_pem_is_clean(tmp_path):
    # A cert with no private key must NOT flag — content, not extension, decides.
    root = _repo(tmp_path, {
        "certs/pub.pem": "-----BEGIN CERTIFICATE-----\nMIIzzz\n-----END CERTIFICATE-----\n",
    })
    result = _native(root)
    assert not [f for f in result.findings if f.category == "F"]


def test_gcp_service_account_json_is_critical(tmp_path):
    sa = json.dumps({
        "type": "service_account",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    })
    root = _repo(tmp_path, {"serviceAccountKey.json": sa})
    result = _native(root)
    assert [f for f in result.findings if f.category == "F" and f.severity == "critical"]


def test_committed_tfstate_is_a_warning(tmp_path):
    root = _repo(tmp_path, {"infra/terraform.tfstate": '{"version":4,"resources":[]}'})
    result = _native(root)
    f = [x for x in result.findings if x.category == "F"]
    assert f and f[0].rule == "committed-tfstate" and f[0].severity == "warning"


def test_openai_key_committed_in_env_is_critical(tmp_path):
    root = _repo(tmp_path, {".env": "OPENAI_API_KEY=sk-proj-" + "c" * 48 + "\n"})
    result = _native(root)
    crit = [f for f in result.findings if f.category == "F" and f.rule == "committed-env-secret"]
    assert crit and crit[0].severity == "critical"


def test_env_example_with_key_shape_is_ignored(tmp_path):
    root = _repo(tmp_path, {".env.example": "OPENAI_API_KEY=sk-proj-" + "d" * 48 + "\n"})
    result = _native(root)
    assert not result.findings, "template env files must never be scanned"


# ---------------------------------------------------------------------------
# category D — more self-hosted engines
# ---------------------------------------------------------------------------

_ES_PUBLIC_NOAUTH = """\
services:
  es:
    image: elasticsearch:8.13.0
    ports: ["9200:9200"]
    environment:
      - xpack.security.enabled=false
"""


def test_elasticsearch_public_with_security_disabled_is_critical(tmp_path):
    root = _repo(tmp_path, {"docker-compose.yml": _ES_PUBLIC_NOAUTH})
    result = _native(root)
    crit = [f for f in result.findings if f.category == "D" and f.severity == "critical"]
    assert crit, "a public Elasticsearch with security disabled must be critical"


def test_new_credential_walk_stays_deterministic(tmp_path):
    root = _repo(tmp_path, {
        "certs/server.pem": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
        "infra/main.tfstate": '{"resources":[]}',
        ".env": "OPENAI_API_KEY=sk-proj-" + "e" * 48 + "\n",
        "dist/app.js": 'const k="sk-ant-' + "z" * 40 + '";',
    })
    a = json.dumps(_native(root).sarif, sort_keys=True)
    b = json.dumps(_native(root).sarif, sort_keys=True)
    assert a == b, "two audits of the same tree must be byte-identical"
