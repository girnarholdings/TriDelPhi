"""The exposure audit — what your shipped product actually leaks.

`tridelphi expose` answers the fear behind "someone can see my code": it audits
the **committed code and config** for the things that are genuinely exposed —
published source maps (a `.map` hands over your whole repo), secrets shipped in
browser bundles, self-hosted databases wired up with no password and a public
port, passwords hashed with md5, tokens parked in localStorage.

It is a *static* audit. It reads files on disk; it cannot reach a running
database or server. A clean result here is not a penetration test, and a flagged
config may already be firewalled — the report says so. Everything runs on your
machine: the native detectors are pure file reads, and the code-pattern rung is
semgrep with a **local, bundled** ruleset (`--config <dir> --metrics off`),
never the registry.

Design: native detectors own the high-confidence, gating findings (public DB +
default password; source-map source disclosure; a live-key-shaped secret in a
shipped bundle). Softer, heuristic code patterns go to semgrep as warnings. All
of it is funneled through the same SARIF containment gate as every wrapped tool.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ladder import SEMGREP_EXPOSURE, ExternalRun, run_tool
from .orchestrate import merge_runs
from .sarif import is_suppressed, simple_sarif
from .severity import SARIF_LEVEL_TO_SEVERITY as _LEVEL_TO_SEV
from .severity import SEVERITY_ORDER

__all__ = ["ExposeFinding", "ExposureResult", "analyze_exposure"]

# Categories, in report order. Each has a plain question and a one-line "what
# these items are" gloss; the guided fix is per finding.
CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("A", "Is your shipped code handing over its own source?",
     "Source maps and secrets that ride along in the browser bundle you deploy."),
    ("B", "Are passwords stored the safe way?",
     "How your code appears to hash passwords before storing them."),
    ("C", "Is user data left sitting in the clear?",
     "Tokens and personal data kept somewhere a script or a leak can read."),
    ("D", "Is a self-hosted database left open?",
     "Database services in your compose/config with no password or a public port."),
    ("E", "Is your shipped JavaScript minified?",
     "Whether you already get minification's baseline protection."),
    ("F", "Are your keys or cloud config committed to the repo?",
     "Private keys, cloud/service-account credentials or terraform state checked into git."),
    ("G", "Are your cloud data rules or storage buckets left open?",
     "Firebase Security Rules that let anyone in, or a bucket set world-readable/writable."),
)
CATEGORY_ORDER = {letter: i for i, (letter, _q, _g) in enumerate(CATEGORIES)}

# Directories never worth walking.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".idea", ".vscode",
})
# Where a web app's shipped output tends to live.
_ASSET_DIRS = ("dist", "build", "out", "public", ".next")
_COMPOSE_RE = re.compile(r"(docker-)?compose.*\.ya?ml$", re.IGNORECASE)
_DB_CONF_NAMES = frozenset({"redis.conf", "mongod.conf", "postgresql.conf", "my.cnf"})

# Committed credential / cloud-config files (category F). Discovered by name/ext,
# then confirmed by content in _detect_committed_credentials — a public cert or a
# `.key` config file that holds no secret produces no finding.
_CRED_EXTS = (".pem", ".key", ".tfstate")
_CRED_NAMES = frozenset({
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    ".npmrc", ".pypirc", ".netrc",
    "credentials.json", "application_default_credentials.json",
})
_CRED_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# One shipped bundle can be large; cap what we read so a hostile/huge file can
# neither hang the audit nor blow memory. Mirrors ladder.py's MAX_OUTPUT_BYTES
# discipline for external tools.
_MAX_READ_BYTES = 8 * 1024 * 1024

# High-confidence secret shapes. Provider-prefixed keys are near-zero false
# positive, so they gate (critical); a JWT can legitimately be public, so it is
# only a warning. Order note: the Anthropic `sk-ant-` pattern precedes the more
# general OpenAI `sk-` one, and OpenAI carries a `(?!ant-)` guard, so an
# Anthropic key is never also reported as an OpenAI key.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("an AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("a Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "critical"),
    ("a Google OAuth client secret", re.compile(r"GOCSPX-[0-9A-Za-z_\-]{20,}"), "critical"),
    ("a Stripe live key", re.compile(r"[sr]k_live_[0-9A-Za-z]{24,}"), "critical"),
    ("an Anthropic API key", re.compile(r"sk-ant-[0-9A-Za-z_\-]{20,}"), "critical"),
    ("an OpenRouter API key", re.compile(r"sk-or-v1-[0-9a-f]{48,}"), "critical"),
    # OpenAI's `sk-` is the most general — it must not swallow Anthropic/OpenRouter,
    # which are matched above, hence the `(?!ant-|or-)` guard.
    ("an OpenAI API key", re.compile(r"sk-(?!ant-|or-)[0-9A-Za-z_\-]{40,}"), "critical"),
    ("a Groq API key", re.compile(r"gsk_[0-9A-Za-z]{40,}"), "critical"),
    ("a HuggingFace token", re.compile(r"hf_[0-9A-Za-z]{34,}"), "critical"),
    ("a Replicate token", re.compile(r"r8_[0-9A-Za-z]{37,}"), "critical"),
    ("a PlanetScale password", re.compile(r"pscale_pw_[0-9A-Za-z._\-]{40,}"), "critical"),
    ("a PlanetScale token", re.compile(r"pscale_tkn_[0-9A-Za-z._\-]{40,}"), "critical"),
    ("a Supabase access token", re.compile(r"sbp_[0-9a-f]{40}"), "critical"),
    ("a Docker personal access token", re.compile(r"dckr_pat_[0-9A-Za-z_\-]{20,}"), "critical"),
    ("a Figma access token", re.compile(r"figd_[0-9A-Za-z_\-]{20,}"), "critical"),
    ("a GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "critical"),
    ("a GitHub fine-grained token", re.compile(r"github_pat_[0-9A-Za-z_]{60,}"), "critical"),
    ("a GitLab access token", re.compile(r"glpat-[0-9A-Za-z_\-]{20,}"), "critical"),
    ("an npm access token", re.compile(r"npm_[0-9A-Za-z]{36}"), "critical"),
    ("a SendGrid API key", re.compile(r"SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}"), "critical"),
    ("a Shopify access token", re.compile(r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}"), "critical"),
    ("a DigitalOcean token", re.compile(r"dop_v1_[0-9a-f]{64}"), "critical"),
    ("a Square access token", re.compile(r"sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}"), "critical"),
    ("a Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "critical"),
    ("a Slack incoming webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_/]{20,}"), "critical"),
    ("a private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("a JSON web token (JWT)", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"), "warning"),
)

# A Firebase web app config is AIza-shaped but PUBLIC by design (it identifies
# the project; it does not grant access). When an AIza key sits next to these
# markers we downgrade it to a note instead of crying "leaked Google key".
_FIREBASE_CONTEXT = re.compile(
    r"(?i)(firebaseConfig|authDomain|firebaseapp\.com|databaseURL|firebasestorage|messagingSenderId)")

# The private-key banner, reused by the committed-credential detector.
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
# An AWS secret access key assignment in a credentials/config file.
_AWS_SECRET_RE = re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[0-9A-Za-z/+]{20,}")
# A registry auth token in .npmrc/.pypirc/.netrc.
_REGISTRY_TOKEN_RE = re.compile(r"(?i)(_authToken|_password|password|\bpassword\b)\s*[=:]")

# Env-var prefixes that build tools INLINE into the client bundle — a secret behind
# one of these ships to every visitor, which is exactly the trap it looks safe.
_PUBLIC_ENV_PREFIXES = (
    "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_",
    "GATSBY_", "VUE_APP_", "NUXT_PUBLIC_",
)
_SECRETY_NAME = re.compile(r"(?i)(secret|private|service_role|\btoken\b|password|api[_-]?key)")


def _public_env_prefix(key: str) -> str | None:
    return next((p for p in _PUBLIC_ENV_PREFIXES if key.upper().startswith(p)), None)


def _first_secret(text: str) -> tuple[str, str, str, str] | None:
    """First ``_SECRET_PATTERNS`` hit in ``text``.

    Returns (label, masked, severity, matched) — ``matched`` is the raw token,
    needed to decode a Supabase JWT's role claim. It never reaches output; only
    ``masked`` is ever printed.
    """
    for label, pattern, severity in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            return label, m.group(0)[:4] + "…", severity, m.group(0)
    return None


def _supabase_role(jwt_token: str) -> str | None:
    """The Supabase `role` claim of a JWT (`service_role` / `anon`), or None.

    Defensive: a malformed or non-Supabase token yields None, so callers fall
    back to treating it as a generic JWT. Pure decode — no network."""
    import base64

    parts = jwt_token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)  # pad base64url
    try:
        data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if role in ("service_role", "anon") else None

# Default/weak database passwords seen in the wild and in tutorials.
_WEAK_DB_PASSWORDS = frozenset({
    "", "postgres", "password", "root", "admin", "mysql", "mongo", "redis",
    "changeme", "secret", "test", "123456", "example", "guest", "minioadmin",
    "neo4j", "elastic", "rabbitmq",
})
_DB_IMAGE_HINTS = (
    "postgres", "mysql", "mariadb", "mongo", "redis", "elasticsearch", "opensearch",
    "rabbitmq", "minio", "couchdb", "neo4j", "clickhouse", "cassandra", "memcached",
)
_DB_URL_RE = re.compile(
    r"(?i)\b(postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://"
    r"[^:@/\s\"']+:([^@/\s\"']+)@"
)


@dataclass(frozen=True, slots=True)
class ExposeFinding:
    category: str          # "A".."G"
    rule: str              # slug, e.g. "source-map-disclosure"
    severity: str          # critical / warning / note
    where: str             # repo-relative "path" or "path:line"
    message: str           # plain-English, self-contained
    fix: str               # what to actually do
    # Other categories this finding is *also* evidence for. A key sitting in a
    # committed `.env` behind a `NEXT_PUBLIC_` prefix is reported once, under
    # category A, because the prefix is the more precise thing to explain — but
    # it is unarguably also an answer to F, "are your keys committed to the
    # repo?". Without this, F printed "all clear" with the key in plain sight,
    # which is a lie to the eye even though the finding is right there above it.
    # The finding still renders once, under `category`; `also` only stops the
    # other row from claiming a clean result it has not earned.
    also: tuple[str, ...] = ()


@dataclass
class ExposureResult:
    findings: list[ExposeFinding] = field(default_factory=list)
    sarif: dict[str, Any] | None = None
    semgrep_ran: bool = False
    semgrep_note: str | None = None

    def gating(self) -> list[ExposeFinding]:
        return [f for f in self.findings if f.severity == "critical"]


# ---------------------------------------------------------------------------
# discovery — expose's own surface, independent of the workflow scan
# ---------------------------------------------------------------------------


def _walk(root: Path) -> Iterable[Path]:
    """Every file under root, sorted, skipping vendored/VCS dirs. Defensive:
    an unreadable directory is skipped, never fatal."""
    stack = [root]
    out: list[Path] = []
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                out.append(entry)
    return sorted(out)


@dataclass
class _Surface:
    compose: list[Path] = field(default_factory=list)
    env: list[Path] = field(default_factory=list)
    db_conf: list[Path] = field(default_factory=list)
    bundles: list[Path] = field(default_factory=list)   # *.js/*.mjs in asset dirs
    maps: list[Path] = field(default_factory=list)       # *.map in asset dirs
    data_files: list[Path] = field(default_factory=list)  # committed csv/sql/seed
    cred_files: list[Path] = field(default_factory=list)  # committed credential/cloud-config files
    cloud_rules: list[Path] = field(default_factory=list)  # *.rules, *.tf (open-access config)
    has_bundler: bool = False


def _in_asset_dir(rel: Path) -> bool:
    return any(part in _ASSET_DIRS for part in rel.parts[:-1])


def _is_cred_file(rel: Path, name: str) -> bool:
    """A file that, by name, might hold committed credentials. Template/example
    variants are skipped; content is confirmed later by the detector."""
    if any(name.endswith(suf) for suf in _CRED_TEMPLATE_SUFFIXES):
        return False
    if name.endswith(".tfstate.backup") or name.endswith(_CRED_EXTS):
        return True
    if name in _CRED_NAMES:
        return True
    if name == "credentials" and rel.parent.name == ".aws":
        return True
    return name.endswith(".json") and any(
        h in name for h in ("serviceaccount", "service-account", "adminsdk"))


def _discover(root: Path) -> _Surface:
    s = _Surface()
    bundler_markers = ("vite.config", "next.config", "webpack.config", "rollup.config")
    for path in _walk(root):
        rel = path.relative_to(root)
        name = path.name.lower()
        if _COMPOSE_RE.search(name):
            s.compose.append(path)
        elif name == ".env" or (name.startswith(".env.") and not name.endswith(
            (".example", ".sample", ".template", ".dist"))):
            s.env.append(path)
        elif name in _DB_CONF_NAMES:
            s.db_conf.append(path)
        elif _in_asset_dir(rel) and path.suffix == ".map":
            s.maps.append(path)
        elif _in_asset_dir(rel) and path.suffix in (".js", ".mjs", ".cjs"):
            s.bundles.append(path)
        elif path.suffix in (".csv", ".sql", ".ndjson") or (
            path.suffix == ".json" and name.startswith("seed")):
            s.data_files.append(path)
        if _is_cred_file(rel, name):
            s.cred_files.append(path)
        if name.endswith((".rules", ".tf", ".tf.json")):
            s.cloud_rules.append(path)
        if name == "package.json" or any(name.startswith(m) for m in bundler_markers):
            s.has_bundler = True
    return s


def _read_text(path: Path, cap: int = _MAX_READ_BYTES) -> str | None:
    try:
        if path.stat().st_size > cap:
            with path.open("rb") as fh:
                return fh.read(cap).decode("utf-8", errors="replace")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# category A — shipped source maps + client secrets
# ---------------------------------------------------------------------------

_FIX_A_MAP = ("turn your bundler's source maps off (Vite `build.sourcemap: false`, "
              "CRA/Next `GENERATE_SOURCEMAP=false`) or use `hidden-source-map`, and "
              "stop deploying `.map` files.")
_FIX_A_SECRET = ("rotate this key now (assume it is compromised — it shipped to every "
                 "visitor) and read it from a server-side endpoint; a browser can never "
                 "keep a secret.")


def _detect_maps_and_secrets(root: Path, surface: _Surface) -> list[ExposeFinding]:
    out: list[ExposeFinding] = []
    for path in surface.maps:
        where = str(path.relative_to(root))
        raw = _read_text(path)
        if raw is None:
            continue
        try:
            doc = json.loads(raw)
        except ValueError:
            out.append(ExposeFinding("A", "source-map-shipped", "warning", where,
                "A source map is deployed alongside your bundle. Even without full "
                "source, it maps minified code back to your structure.", _FIX_A_MAP))
            continue
        sources = doc.get("sourcesContent") if isinstance(doc, dict) else None
        if isinstance(sources, list) and any(isinstance(s, str) and s.strip() for s in sources):
            n = sum(1 for s in sources if isinstance(s, str) and s.strip())
            out.append(ExposeFinding("A", "source-map-disclosure", "critical", where,
                f"Full source disclosure: this shipped source map embeds {n} original "
                "source file(s) verbatim (comments and all). Anyone who loads your site "
                "can reconstruct your repository.", _FIX_A_MAP))
        else:
            out.append(ExposeFinding("A", "source-map-shipped", "warning", where,
                "A source map is deployed alongside your bundle; it maps minified code "
                "back to your original structure.", _FIX_A_MAP))

    for path in surface.bundles:
        raw = _read_text(path)
        if raw is None:
            continue
        where = str(path.relative_to(root))
        firebase = bool(_FIREBASE_CONTEXT.search(raw))
        for label, pattern, severity in _SECRET_PATTERNS:
            m = pattern.search(raw)
            if not m:
                continue
            masked = m.group(0)[:4] + "…"
            line = raw.count("\n", 0, m.start()) + 1
            # A Firebase web apiKey is AIza-shaped but public by design — not a leak.
            if label == "a Google API key" and firebase:
                out.append(ExposeFinding("A", "firebase-public-key", "note",
                    f"{where}:{line}",
                    f"This is a Firebase web API key ({masked}). Unlike a normal secret it "
                    "is meant to ship in the browser — it names your project, it does not "
                    "grant access. Your real protection is server-side Security Rules.",
                    "no need to hide this key; make sure your Firestore/Storage Security "
                    "Rules actually restrict who can read and write your data."))
                continue
            # A Supabase key is a JWT: the `service_role` key bypasses Row Level
            # Security and must never ship; the `anon` key is public by design.
            if label.endswith("(JWT)") and (role := _supabase_role(m.group(0))):
                if role == "service_role":
                    out.append(ExposeFinding("A", "supabase-service-role", "critical",
                        f"{where}:{line}",
                        f"A Supabase service_role key ({masked}) is shipped in your bundle. "
                        "It bypasses Row Level Security — anyone who reads it has full, "
                        "unrestricted access to your database.",
                        "rotate this key immediately and never expose service_role to the "
                        "browser; the client should use the anon key plus RLS policies."))
                else:
                    out.append(ExposeFinding("A", "supabase-anon-key", "note",
                        f"{where}:{line}",
                        f"This is a Supabase anon key ({masked}). Like a Firebase web key it "
                        "is meant to ship in the browser; it grants nothing on its own.",
                        "no need to hide it; your protection is Row Level Security — make "
                        "sure RLS is enabled on every table with real policies."))
                continue
            out.append(ExposeFinding("A", "client-secret", severity,
                f"{where}:{line}",
                f"What looks like {label} ({masked}) is shipped inside your browser "
                "bundle. Anything in browser code is readable by anyone who loads the "
                "page — obfuscation cannot hide it.", _FIX_A_SECRET))
    return out


_FIX_PUBLIC_ENV = ("give it a non-public name (drop the NEXT_PUBLIC_/VITE_/… prefix) and read "
                   "it only on the server; anything with that prefix is compiled into the "
                   "browser bundle. Rotate it if it was a real secret.")

# A `NEXT_PUBLIC_FIREBASE_API_KEY` is AIza-shaped and looks exactly like a leaked
# Google API key — but a Firebase *web* config key is public by design, and we
# already say so when we find one in a bundle. Saying the opposite about the same
# key because it was found in `.env` instead is the kind of contradiction that
# costs a tool its credibility on the one screen where it had the reader's trust.
_FIREBASE_ENV_NAME = re.compile(r"(?i)firebase")


def _detect_public_env(root: Path, surface: _Surface) -> list[ExposeFinding]:
    """A secret behind a framework 'public' env prefix — it ships to the browser.

    Distinct from the committed-secret case (category F): here the *prefix* is the
    danger, so the message and fix are about the prefix, not about committing. The
    findings still carry ``also=("F",)`` so F's row cannot report "all clear" while
    a real key sits in a committed `.env`.

    Public-by-design keys (Firebase web config, Supabase `anon`) are graded the
    same way here as they are in a bundle: a note, not a critical. The one that
    inverts is Supabase `service_role` — behind a public prefix it is worse than a
    plain committed secret, because the build tool ships it to every visitor.
    """
    out: list[ExposeFinding] = []
    for path in surface.env:
        raw = _read_text(path)
        if raw is None:
            continue
        where_file = str(path.relative_to(root))
        for i, ln in enumerate(raw.splitlines(), 1):
            stripped = ln.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _sep, value = stripped.partition("=")
            key, value = key.strip(), value.strip().strip("\"'")
            prefix = _public_env_prefix(key)
            if prefix is None or not value:
                continue
            where = f"{where_file}:{i}"
            hit = _first_secret(value)
            if hit:
                label, masked, severity, matched = hit
                if label == "a Google API key" and _FIREBASE_ENV_NAME.search(key):
                    out.append(ExposeFinding("A", "firebase-public-key", "note", where,
                        f"`{key}` is a Firebase web API key ({masked}). Unlike a normal "
                        "secret it is meant to ship in the browser — it names your project, "
                        "it does not grant access. Your real protection is server-side "
                        "Security Rules.",
                        "no need to hide this key; make sure your Firestore/Storage Security "
                        "Rules actually restrict who can read and write your data."))
                    continue
                if label.endswith("(JWT)") and (role := _supabase_role(matched)):
                    if role == "service_role":
                        out.append(ExposeFinding("A", "supabase-service-role", "critical",
                            where,
                            f"`{key}` is a Supabase service_role key ({masked}) behind the "
                            f"`{prefix}` prefix, so your build tool inlines it into the "
                            "browser bundle. It bypasses Row Level Security — every visitor "
                            "gets full, unrestricted access to your database.",
                            "rotate this key immediately and never expose service_role to "
                            "the browser; the client should use the anon key plus RLS "
                            "policies.", ("F",)))
                    else:
                        out.append(ExposeFinding("A", "supabase-anon-key", "note", where,
                            f"`{key}` is a Supabase anon key ({masked}). Like a Firebase web "
                            "key it is meant to ship in the browser; it grants nothing on "
                            "its own.",
                            "no need to hide it; your protection is Row Level Security — "
                            "make sure RLS is enabled on every table with real policies."))
                    continue
                if severity == "critical":
                    out.append(ExposeFinding("A", "public-env-secret", "critical", where,
                        f"`{key}` holds what looks like a real key ({masked}). The `{prefix}` "
                        "prefix makes your build tool inline it into the browser bundle, so it "
                        "ships to every visitor.", _FIX_PUBLIC_ENV, ("F",)))
                    continue
            if _SECRETY_NAME.search(key) and len(value) >= 8:
                out.append(ExposeFinding("A", "public-env-suspicious", "warning", where,
                    f"`{key}` is named like a secret but carries the `{prefix}` prefix, which "
                    "ships its value to the browser. If it is sensitive, it is exposed.",
                    _FIX_PUBLIC_ENV, ("F",)))
    return out


# ---------------------------------------------------------------------------
# category D — self-hosted DB / service misconfig
# ---------------------------------------------------------------------------

_FIX_D = ("bind the DB port to `127.0.0.1:` (or drop `ports:` and use the compose "
          "network), and set a strong password from a secret — never a default.")


def _compose_line(node: Any, key: str) -> int | None:
    """Best-effort 1-based line for `key` in a ruamel round-trip mapping."""
    try:
        return node.lc.key(key)[0] + 1  # type: ignore[union-attr]
    except (AttributeError, KeyError, TypeError, IndexError):
        return None


def _port_is_public(entry: Any) -> bool:
    """A compose ports entry that publishes to the host (not 127.0.0.1)."""
    text = ""
    if isinstance(entry, str):
        text = entry
    elif isinstance(entry, dict):
        host_ip = str(entry.get("host_ip", ""))
        if host_ip:
            return host_ip not in ("127.0.0.1", "::1", "localhost")
        return entry.get("published") is not None
    if not text:
        return False
    if text.startswith(("127.0.0.1:", "localhost:", "::1:")):
        return False
    # "5432:5432", "0.0.0.0:5432:5432", "5432" all publish to the host.
    return ":" in text or text.strip().isdigit()


def _detect_db_misconfig(root: Path, surface: _Surface) -> list[ExposeFinding]:
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    out: list[ExposeFinding] = []
    yaml = YAML(typ="rt")

    for path in surface.compose:
        raw = _read_text(path)
        if raw is None:
            continue
        where_file = str(path.relative_to(root))
        try:
            doc = yaml.load(raw)
        except (YAMLError, ValueError, TypeError):
            continue
        if not isinstance(doc, dict):
            continue
        services = doc.get("services")
        if not isinstance(services, dict):
            continue
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            image = str(svc.get("image", "")) + " " + str(name)
            if not any(hint in image.lower() for hint in _DB_IMAGE_HINTS):
                continue
            line = _compose_line(services, name)
            where = f"{where_file}:{line}" if line else where_file

            ports = svc.get("ports")
            public = isinstance(ports, list) and any(_port_is_public(p) for p in ports)

            # environment may be a mapping (KEY: value) or a list ("KEY=value").
            pairs: list[tuple[str, str]] = []
            env = svc.get("environment")
            if isinstance(env, dict):
                pairs = [(str(k), str(v)) for k, v in env.items()]
            elif isinstance(env, list):
                pairs = [(s.partition("=")[0], s.partition("=")[2])
                         for s in (str(item) for item in env)]
            weak_pw = False
            no_auth = False
            for key, val in pairs:
                ku = key.upper()
                vv = val.strip().strip("\"'").lower()
                if "PASSWORD" in ku and vv in _WEAK_DB_PASSWORDS:
                    weak_pw = True
                if ku in ("ALLOW_EMPTY_PASSWORD", "ALLOW_ANONYMOUS_LOGIN") and vv in ("yes", "true", "1"):
                    no_auth = True
                # Engine-specific "auth turned off" switches.
                if ku == "NEO4J_AUTH" and vv == "none":
                    no_auth = True
                if "SECURITY.ENABLED" in ku and vv in ("false", "0", "no"):
                    no_auth = True  # elasticsearch xpack.security.enabled=false
                if ku in ("DISABLE_SECURITY_PLUGIN", "PLUGINS.SECURITY.DISABLED") and vv in ("true", "1", "yes"):
                    no_auth = True  # opensearch

            db = next((h for h in _DB_IMAGE_HINTS if h in image.lower()), "database")
            if public and (weak_pw or no_auth):
                out.append(ExposeFinding("D", "db-public-open", "critical", where,
                    f"The `{name}` {db} service publishes its port to the host and has "
                    "no real password (default/empty/auth disabled). If that host is "
                    "reachable, anyone can connect and read everything.", _FIX_D))
            elif public:
                out.append(ExposeFinding("D", "db-public-bind", "warning", where,
                    f"The `{name}` {db} service publishes its port to the host. If this "
                    "isn't firewalled, it's reachable from outside — bind it to "
                    "127.0.0.1 or drop `ports:`.", _FIX_D))
            elif weak_pw or no_auth:
                out.append(ExposeFinding("D", "db-weak-password", "warning", where,
                    f"The `{name}` {db} service uses a default/empty password or has auth "
                    "disabled. Set a strong password from a secret.", _FIX_D))

    for path in surface.env:
        raw = _read_text(path)
        if raw is None:
            continue
        where_file = str(path.relative_to(root))
        for i, ln in enumerate(raw.splitlines(), 1):
            m = _DB_URL_RE.search(ln)
            if m:
                out.append(ExposeFinding("D", "db-url-credential", "warning",
                    f"{where_file}:{i}",
                    "A database URL with an inline username:password is committed here. "
                    "Rotate the credential and keep it out of committed files.", _FIX_D,
                    ("F",)))
                break
    return out


# ---------------------------------------------------------------------------
# category E — minification status (informational)
# ---------------------------------------------------------------------------


def _looks_minified(text: str) -> bool:
    head = text[:200_000]
    if not head.strip():
        return False
    lines = head.splitlines() or [head]
    longest = max((len(ln) for ln in lines), default=0)
    ws = sum(c.isspace() for c in head) / max(len(head), 1)
    return longest > 500 or (longest > 200 and ws < 0.15)


def _detect_minification(root: Path, surface: _Surface) -> list[ExposeFinding]:
    if not surface.bundles:
        return []
    # Look at the largest few bundles for a representative verdict.
    ranked = sorted(surface.bundles, key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)
    checked = 0
    minified = 0
    for path in ranked[:5]:
        raw = _read_text(path, cap=1_000_000)
        if raw is None:
            continue
        checked += 1
        if _looks_minified(raw):
            minified += 1
    if not checked:
        return []
    if minified >= checked:
        return [ExposeFinding("E", "minified", "note", "shipped JavaScript",
            "Your shipped JavaScript is already minified — you already get "
            "minification's modest protection (comments and names are gone). An "
            "obfuscator would add little on top.",
            "nothing to do here; `tridelphi privatize` is optional and adds little.")]
    return [ExposeFinding("E", "not-minified", "note", "shipped JavaScript",
        "Your shipped JavaScript does not look minified. Turning on your bundler's "
        "built-in minifier is the first, free step — it strips comments and names "
        "irreversibly.",
        "enable your bundler's minifier (terser/esbuild); it's usually one setting.")]


# ---------------------------------------------------------------------------
# category C (native slice) — committed data files with sensitive columns
# ---------------------------------------------------------------------------

_SENSITIVE_COLUMN = re.compile(
    r"(?i)\b(password|passwd|pwd|ssn|social_security|credit_card|card_number|cvv)\b")
_FIX_C_DATA = ("don't commit real user data; if this is a fixture, use fake values, "
               "and never store passwords/PII in plaintext.")


def _detect_committed_pii(root: Path, surface: _Surface) -> list[ExposeFinding]:
    out: list[ExposeFinding] = []
    for path in surface.data_files:
        raw = _read_text(path, cap=1_000_000)
        if raw is None:
            continue
        head = raw[:8192]
        m = _SENSITIVE_COLUMN.search(head)
        if m:
            where = str(path.relative_to(root))
            out.append(ExposeFinding("C", "committed-sensitive-data", "warning", where,
                f"A committed data file has a `{m.group(1).lower()}` column/field. If this "
                "is real user data, it is exposed to anyone with repo access and likely "
                "stored in plaintext.", _FIX_C_DATA))
    return out


# ---------------------------------------------------------------------------
# category F — committed credential / cloud-config files
# ---------------------------------------------------------------------------

_FIX_CRED = ("remove it from the repo, rotate the credential (assume it is compromised — "
             "it is in your git history) and load it from a secret at runtime instead.")


def _detect_committed_credentials(root: Path, surface: _Surface) -> list[ExposeFinding]:
    """Confirm, by content, which discovered credential-shaped files actually hold
    a secret. A public certificate or a keyless `.key` config file produces nothing.
    Overlaps L1 gitleaks in CI on purpose — this rung is offline and needs no tool."""
    out: list[ExposeFinding] = []
    for path in surface.cred_files:
        raw = _read_text(path)
        if raw is None:
            continue
        where = str(path.relative_to(root))
        name = path.name.lower()

        if _PRIVATE_KEY_RE.search(raw):
            out.append(ExposeFinding("F", "committed-private-key", "critical", where,
                "A private key is committed here. Anyone with repo access — now or "
                "anywhere in your git history — has it.", _FIX_CRED))
        elif '"service_account"' in raw and "private_key" in raw:
            out.append(ExposeFinding("F", "committed-service-account", "critical", where,
                "A cloud service-account key file is committed here; it grants "
                "programmatic access to your cloud project.", _FIX_CRED))
        elif _AWS_SECRET_RE.search(raw):
            out.append(ExposeFinding("F", "committed-aws-credential", "critical", where,
                "An AWS secret access key is committed in this credentials file.", _FIX_CRED))
        elif (hit := _first_secret(raw)) and hit[2] == "critical":
            label, masked, _sev, _matched = hit
            out.append(ExposeFinding("F", "committed-secret-file", "critical", where,
                f"What looks like {label} ({masked}) is committed in this file.", _FIX_CRED))
        elif name.endswith((".tfstate", ".tfstate.backup")):
            out.append(ExposeFinding("F", "committed-tfstate", "warning", where,
                "Terraform state is committed here. State records every resource attribute "
                "in plaintext, which routinely includes generated passwords and keys.",
                "keep state in a remote backend (S3/GCS/Terraform Cloud), not in git; "
                "rotate anything sensitive it already captured."))
        elif name in (".npmrc", ".pypirc", ".netrc") and _REGISTRY_TOKEN_RE.search(raw):
            out.append(ExposeFinding("F", "committed-registry-token", "warning", where,
                "This committed file looks like it holds a registry auth token or password; "
                "anyone with repo access can publish or pull as you.",
                "move the token to an untracked file or an env var, and rotate it."))

    # A committed (non-template) .env that carries a real, provider-shaped key — the
    # classic vibe-coder mistake (`OPENAI_API_KEY=sk-…` checked in). The DB-URL case
    # is category D; this is the raw-secret case.
    for path in surface.env:
        raw = _read_text(path)
        if raw is None:
            continue
        where_file = str(path.relative_to(root))
        for i, ln in enumerate(raw.splitlines(), 1):
            # A public-prefixed line (NEXT_PUBLIC_/VITE_/…) is owned by category A
            # (`_detect_public_env`), whose message about the prefix is more precise.
            key = ln.split("=", 1)[0].strip()
            if _public_env_prefix(key):
                continue
            hit = _first_secret(ln)
            if hit and hit[2] == "critical":
                label, masked, _sev, _matched = hit
                out.append(ExposeFinding("F", "committed-env-secret", "critical",
                    f"{where_file}:{i}",
                    f"What looks like {label} ({masked}) is committed in this env file. "
                    "Anyone with repo access — and your whole git history — has it.", _FIX_CRED))
                break
    return out


# ---------------------------------------------------------------------------
# category G — open cloud data rules & public storage buckets
# ---------------------------------------------------------------------------

# A Firebase/Firestore/Storage rule that grants access with `if true` — wide open.
_OPEN_FIREBASE_RULE = re.compile(r"(?is)\ballow\b[^;{}]*:\s*if\s+true\b")
# A world-open storage grant in IaC (public-read-write ACL, or an allUsers binding).
_PUBLIC_BUCKET_ACL = re.compile(r'(?i)("?public-read-write"?|\ballUsers\b|\ballAuthenticatedUsers\b)')

_FIX_G_RULES = ("replace `if true` with real conditions — e.g. `if request.auth != null` plus "
                "per-document ownership checks; an open rule exposes your whole database.")
_FIX_G_BUCKET = ("remove the world-readable/writable grant; scope access to specific principals "
                 "and use signed URLs for anything that must be shared.")


def _detect_open_cloud_rules(root: Path, surface: _Surface) -> list[ExposeFinding]:
    """Open Firebase Security Rules (`allow …: if true`) and world-open bucket ACLs.

    This completes the Firebase story: the public-key note tells you to lock down
    Security Rules — here we flag when they are wide open."""
    out: list[ExposeFinding] = []
    for path in surface.cloud_rules:
        raw = _read_text(path)
        if raw is None:
            continue
        where = str(path.relative_to(root))
        name = path.name.lower()
        if name.endswith(".rules"):
            if _OPEN_FIREBASE_RULE.search(raw):
                out.append(ExposeFinding("G", "open-firebase-rules", "critical", where,
                    "A Security Rule here grants access with `if true` — anyone, "
                    "authenticated or not, can read and write your database.", _FIX_G_RULES))
        elif _PUBLIC_BUCKET_ACL.search(raw):  # *.tf / *.tf.json
            out.append(ExposeFinding("G", "public-bucket", "warning", where,
                "This infrastructure config grants public (world) access to a storage "
                "bucket. If that isn't intentional, anyone on the internet can reach it.",
                _FIX_G_BUCKET))
    return out


# ---------------------------------------------------------------------------
# category B + C (code) — semgrep with the local ruleset
# ---------------------------------------------------------------------------

# Map our rule metadata / rule-id substring to a category + plain fix.
_SEMGREP_RULE_MAP = {
    "weak-password-hash": ("B", "hash passwords with argon2id or bcrypt (cost >= 12), never md5/sha1/sha256."),
    "token-in-web-storage": ("C", "keep session tokens in an HttpOnly, Secure cookie, not localStorage."),
    "hardcoded-db-credential": ("C", "read DB credentials from a server-side env var or secret; rotate this one."),
    "jwt-verify-disabled": ("C", "never disable JWT signature verification or allow the 'none' algorithm; pin the expected algorithm and verify."),
    "tls-verify-disabled": ("C", "keep TLS certificate verification on; fix the certificate chain instead of disabling checks."),
}


def _semgrep_category(rule_id: str) -> tuple[str, str]:
    for key, (cat, fix) in _SEMGREP_RULE_MAP.items():
        if key in rule_id:
            return cat, fix
    return "B", "review this pattern; the message names the file and line."


def _findings_from_semgrep(document: dict[str, Any]) -> list[ExposeFinding]:
    out: list[ExposeFinding] = []
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            if is_suppressed(result):
                continue  # audited & accepted in source (# nosemgrep)
            rule_id = str(result.get("ruleId", ""))
            cat, fix = _semgrep_category(rule_id)
            level = result.get("level")
            severity = _LEVEL_TO_SEV.get(level if isinstance(level, str) else "", "warning")
            msg = result.get("message")
            text = msg.get("text", "") if isinstance(msg, dict) else ""
            where = _first_location(result)
            out.append(ExposeFinding(cat, rule_id.split(".")[-1] or "pattern", severity,
                                     where, _clean(text), fix))
    return out


def _first_location(result: dict[str, Any]) -> str:
    locs = result.get("locations")
    if isinstance(locs, list) and locs and isinstance(locs[0], dict):
        phys = locs[0].get("physicalLocation") or {}
        if isinstance(phys, dict):
            art = phys.get("artifactLocation") or {}
            region = phys.get("region") or {}
            uri = art.get("uri", "") if isinstance(art, dict) else ""
            line = region.get("startLine") if isinstance(region, dict) else None
            if isinstance(uri, str) and uri:
                return f"{uri}:{line}" if isinstance(line, int) else uri
    return ""


def _clean(text: str) -> str:
    return " ".join(str(text).split())[:300] or "(no description given)"


# ---------------------------------------------------------------------------
# SARIF assembly for the native findings
# ---------------------------------------------------------------------------

_HELP_URI = "https://girnarholdings.github.io/TriDelPhi/"


def _native_sarif(findings: list[ExposeFinding], tool_version: str) -> dict[str, Any]:
    return simple_sarif(
        findings,
        tool="tridelphi-expose",
        audit_label="Exposure audit",
        tool_version=tool_version,
        help_uri=_HELP_URI,
    )


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def analyze_exposure(root: str | Path, *, tool_version: str = "0", run_semgrep: bool = True) -> ExposureResult:
    """Audit ``root`` for shipped-asset, DB-config, and data-hygiene exposure.

    Native detectors are pure file reads (no subprocess, no network). The
    code-pattern rung runs semgrep with the bundled local ruleset when semgrep
    is on PATH and ``run_semgrep`` is set; if it is absent, the audit still
    produces every native finding and notes that the code rung was skipped.
    """
    root = Path(root)
    surface = _discover(root)

    findings: list[ExposeFinding] = []
    findings += _detect_maps_and_secrets(root, surface)
    findings += _detect_public_env(root, surface)
    findings += _detect_db_misconfig(root, surface)
    findings += _detect_committed_pii(root, surface)
    findings += _detect_committed_credentials(root, surface)
    findings += _detect_open_cloud_rules(root, surface)
    findings += _detect_minification(root, surface)

    semgrep_ran = False
    semgrep_note: str | None = None
    document = _native_sarif(findings, tool_version)

    if run_semgrep:
        ext: ExternalRun = run_tool(SEMGREP_EXPOSURE, str(root))
        if ext.sarif is not None:
            semgrep_ran = True
            findings += _findings_from_semgrep(ext.sarif)
            document = merge_runs(document, ext.sarif)
        elif ext.diagnostic is not None:
            semgrep_note = ext.diagnostic.message

    findings.sort(key=lambda f: (CATEGORY_ORDER.get(f.category, 9),
                                 SEVERITY_ORDER.get(f.severity, 3),
                                 f.where, f.rule))
    return ExposureResult(
        findings=findings, sarif=document, semgrep_ran=semgrep_ran, semgrep_note=semgrep_note,
    )
