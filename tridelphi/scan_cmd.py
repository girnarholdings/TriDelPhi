"""`tridelphi scan` — the pre-install trust audit, rendered for a human.

The person running this is one command away from installing something a chat
window handed them. The report has one job: make "should I run the installer?"
answerable in thirty seconds, with the verdict first and the evidence under it.

Targets, in order of trust required:

  a directory        — a cloned repo or unpacked download. Pure file reads.
  an archive         — .tgz / .tar.gz / .zip / .whl, extracted safely to a
                       temp dir first. Still no execution.
  npm:<package>      — downloads the npmjs registry tarball via a bounded
                       HTTPS GET, checks its digest, and scans it. Never npm.
  pypi:<package>     — downloads the sdist/wheel straight from PyPI's JSON API
                       with a plain HTTP GET and scans it. Deliberately NOT
                       `pip download`, which can execute a hostile setup.py
                       just to resolve metadata.

The registry forms are the tool's only network use, they exist so the scan can
happen *before* the install, and they say so out loud before connecting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TextIO

from .fsutil import atomic_write_text
from .preflight import (
    CATEGORIES,
    PreflightFinding,
    PreflightResult,
    analyze_preflight,
    extract_archive,
)
from .reportutil import grouped_lines, md_escape, wrap
from .sarif import dumps
from .severity import should_fail

__all__ = ["run_scan"]

_SCOPE = (
    "Read files only — nothing was installed, executed, or sandboxed. This "
    "catches the known shapes of install-time attacks in source and config; it "
    "cannot judge a compiled binary, and a clean result is not proof of safety."
)
_MAX_ITEMS = 6
_ARCHIVE_EXTS = (".tgz", ".tar.gz", ".tar", ".tar.bz2", ".tar.xz", ".zip", ".whl")
_MAX_METADATA_BYTES = 2 * 1024 * 1024
_MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
_NPM_NAME_SEGMENT = r"[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,212}[A-Za-z0-9._~-])?"
_NPM_SPEC = re.compile(
    rf"^(?P<name>(?:@{_NPM_NAME_SEGMENT}/{_NPM_NAME_SEGMENT}|{_NPM_NAME_SEGMENT}))"
    r"(?:@(?P<version>[A-Za-z0-9](?:[A-Za-z0-9._+~-]{0,126}[A-Za-z0-9._+~-])?))?$",
    re.ASCII,
)

_NAME_HELP = """\
tridelphi: {arg!r} is not a path here. To scan something you haven't downloaded:

  tridelphi scan npm:{arg}     fetch the npm tarball (no scripts run) and scan it
  tridelphi scan pypi:{arg}    download the PyPI artifact (never pip) and scan it

Or download it yourself and point at the result:

  tridelphi scan ./some-clone/        a directory
  tridelphi scan ./package.tgz        an archive

Both registry forms use the network, once, to download only. Nothing installs.
"""


# ---------------------------------------------------------------------------
# target resolution
# ---------------------------------------------------------------------------


def _fetch_npm(spec: str, tmp: Path, err: TextIO) -> Path | None:
    """Download one registry package tarball without executing lifecycle scripts."""
    match = _NPM_SPEC.fullmatch(spec)
    if match is None or len(match.group("name")) > 214:
        print(
            "tridelphi: npm target must be a registry package name, optionally "
            "followed by one exact version or tag (URLs, paths and ranges are refused)",
            file=err,
        )
        return None
    print(f"tridelphi: fetching {spec} from the npm registry (network; download "
          "only, no scripts run)…", file=err)
    name = match.group("name")
    version = match.group("version") or "latest"
    url = (
        "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")
        + "/" + urllib.parse.quote(version, safe="")
    )
    target = tmp / "npm-package.tgz"
    downloaded = False
    try:
        with _open_https(url, timeout=60, allow_hosts={"registry.npmjs.org"}) as response:
            meta = json.loads(_read_limited(response, _MAX_METADATA_BYTES))
        if not isinstance(meta, dict) or meta.get("name") != name or not isinstance(meta.get("dist"), dict):
            raise ValueError("npm returned malformed or mismatched package metadata")
        dist = meta["dist"]
        artifact_url = dist.get("tarball")
        integrity = dist.get("integrity")
        if not isinstance(artifact_url, str) or not isinstance(integrity, str):
            raise ValueError("npm returned no tarball with a strong integrity digest")
        # Require SHA-512 or SHA-256 instead of silently falling back to SHA-1.
        tokens = integrity.split()
        token = next((item for algorithm in ("sha512", "sha256") for item in tokens if item.startswith(algorithm + "-")), None)
        if token is None:
            raise ValueError("npm artifact needs a SHA-512 or SHA-256 integrity digest")
        algorithm, encoded = token.split("-", 1)
        expected = base64.b64decode(encoded, validate=True)
        if len(expected) != hashlib.new(algorithm).digest_size:
            raise ValueError("npm returned a malformed integrity digest")
        with _open_https(artifact_url, timeout=180, allow_hosts={"registry.npmjs.org"}) as response:
            actual = _copy_limited(response, target, _MAX_DOWNLOAD_BYTES, algorithm=algorithm)
        downloaded = True
        if actual != expected.hex():
            raise ValueError("download integrity does not match npm metadata")
    except Exception as exc:
        if downloaded:
            target.unlink(missing_ok=True)
        print(f"tridelphi: npm download refused: {exc}", file=err)
        return None
    return target


# The only hosts this tool will fetch from. A scan target is untrusted by
# definition, and the artifact URL in a PyPI response is attacker-influenceable
# (a compromised index, a MITM, a typosquat's own metadata) — so the download
# URL is validated against this set, not trusted because PyPI returned it.
_PYPI_METADATA_HOST = "pypi.org"
_PYPI_ARTIFACT_HOSTS = frozenset({"files.pythonhosted.org", "pypi.org"})


def _validate_https_url(url: str, allow_hosts: frozenset[str] | set[str]) -> None:
    parsed = urllib.parse.urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allow_hosts
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"refusing a non-https or off-allowlist URL: {url[:80]}")


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_hosts: frozenset[str] | set[str]) -> None:
        self._allow_hosts = allow_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_https_url(newurl, self._allow_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_https(url: str, *, timeout: int, allow_hosts: frozenset[str] | set[str]):
    """Open ``url`` only if it is HTTPS on an allowed host.

    ``urllib`` honours whatever scheme it is handed — `file://`, `ftp://`,
    `gopher://` — so a dynamic URL that reaches `urlopen` unchecked can read a
    local file or hit an internal service. This gate is the difference between
    "download from PyPI" and "fetch whatever a hostile response names": the
    scheme must be https and the host must be one we chose, or it does not open.
    """
    _validate_https_url(url, allow_hosts)
    # Audited (semgrep dynamic-urllib-use): the two lines above ARE the mitigation
    # this rule asks for — the scheme is pinned to https and the host to a caller-
    # supplied allowlist, so a file:// or off-host URL never reaches urlopen. This
    # is the sole urlopen in the tool, funnelled here so the check can't be bypassed.
    # nosemgrep
    opener = urllib.request.build_opener(_AllowlistedRedirectHandler(allow_hosts))
    return opener.open(url, timeout=timeout)


def _content_length(response) -> int | None:
    value = response.headers.get("Content-Length")
    if value is None:
        return None
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise ValueError("server returned an invalid Content-Length") from None
    if length < 0:
        raise ValueError("server returned a negative Content-Length")
    return length


def _read_limited(response, limit: int) -> bytes:
    declared = _content_length(response)
    if declared is not None and declared > limit:
        raise ValueError(f"response exceeds the {limit // (1024 * 1024)} MiB size cap")
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"response exceeds the {limit // (1024 * 1024)} MiB size cap")
    return payload


def _copy_limited(response, target: Path, limit: int, *, algorithm: str = "sha256") -> str:
    declared = _content_length(response)
    if declared is not None and declared > limit:
        raise ValueError(f"download exceeds the {limit // (1024 * 1024)} MiB size cap")
    digest = hashlib.new(algorithm)
    written = 0
    created = False
    try:
        with target.open("xb") as output:
            created = True
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                if written > limit:
                    raise ValueError(
                        f"download exceeds the {limit // (1024 * 1024)} MiB size cap"
                    )
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        if created:
            target.unlink(missing_ok=True)
        raise
    return digest.hexdigest()


def _fetch_pypi(spec: str, tmp: Path, err: TextIO) -> Path | None:
    """Download a PyPI artifact with a plain GET against the JSON API.

    Never `pip download`: resolving an sdist's metadata can execute its
    setup.py, which is precisely the code we refuse to run before reading.

    Every fetch is scheme- and host-validated (`_open_https`): the metadata URL
    is built with the package name percent-encoded so it cannot break out of the
    path, and the artifact URL PyPI hands back is checked against the
    pythonhosted allowlist rather than trusted on sight."""
    name, _sep, version = spec.partition("==")
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    url = (f"https://pypi.org/pypi/{quoted_name}/{quoted_version}/json" if version
           else f"https://pypi.org/pypi/{quoted_name}/json")
    print(f"tridelphi: fetching {spec} metadata from PyPI (network; download "
          "only, nothing executed)…", file=err)
    try:
        with _open_https(url, timeout=60, allow_hosts={_PYPI_METADATA_HOST}) as resp:
            meta = json.loads(_read_limited(resp, _MAX_METADATA_BYTES))
    except Exception as exc:
        print(f"tridelphi: PyPI lookup failed for {name}: {exc}", file=err)
        return None
    if not isinstance(meta, dict) or not isinstance(meta.get("urls"), list):
        print(f"tridelphi: PyPI returned malformed metadata for {spec}", file=err)
        return None
    urls = [entry for entry in meta["urls"] if isinstance(entry, dict)]
    chosen = next((u for u in urls if u.get("packagetype") == "sdist"),
                  next(iter(urls), None))
    if not chosen or not isinstance(chosen.get("url"), str):
        print(f"tridelphi: PyPI lists no downloadable artifact for {spec}", file=err)
        return None
    # PyPI serves artifacts from files.pythonhosted.org; a URL pointing anywhere
    # else — least of all a file:// or an internal host — is a red flag, not a
    # download target.
    artifact_url = chosen["url"]
    filename_value = chosen.get("filename")
    if (
        not isinstance(filename_value, str)
        or not filename_value
        or Path(filename_value).name != filename_value
        or "\\" in filename_value
        or not filename_value.lower().endswith(_ARCHIVE_EXTS)
    ):
        print(f"tridelphi: PyPI returned an unsafe artifact filename for {spec}", file=err)
        return None
    digests = chosen.get("digests")
    expected_sha256 = digests.get("sha256") if isinstance(digests, dict) else None
    if (
        not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None
    ):
        print(f"tridelphi: PyPI returned no valid sha256 digest for {spec}", file=err)
        return None
    filename = filename_value
    target = tmp / filename
    if target.exists() or target.is_symlink():
        print(f"tridelphi: refusing to overwrite an existing file named {filename}", file=err)
        return None
    downloaded = False
    try:
        with _open_https(artifact_url, timeout=180, allow_hosts=_PYPI_ARTIFACT_HOSTS) as resp:
            actual_sha256 = _copy_limited(resp, target, _MAX_DOWNLOAD_BYTES)
        downloaded = True
        if actual_sha256.lower() != expected_sha256.lower():
            raise ValueError("download sha256 does not match PyPI metadata")
    except ValueError as exc:
        if downloaded:
            target.unlink(missing_ok=True)
        print(f"tridelphi: {exc}", file=err)
        print(f"tridelphi: refusing the PyPI artifact for {spec}.", file=err)
        return None
    except Exception as exc:
        if downloaded:
            target.unlink(missing_ok=True)
        print(f"tridelphi: download failed: {exc}", file=err)
        return None
    return target


def _resolve_target(arg: str, tmp: Path, err: TextIO) -> Path | None:
    """Turn the CLI argument into a directory to analyze, or None (error
    already printed)."""
    if arg.startswith("npm:"):
        archive = _fetch_npm(arg[4:], tmp, err)
    elif arg.startswith(("pypi:", "pip:")):
        archive = _fetch_pypi(arg.split(":", 1)[1], tmp, err)
    else:
        p = Path(arg)
        if p.is_dir():
            return p
        if p.is_file() and p.name.lower().endswith(_ARCHIVE_EXTS):
            archive = p
        elif p.exists():
            print(f"tridelphi: {arg} is not a directory or a supported archive "
                  f"({', '.join(_ARCHIVE_EXTS)}). A compiled installer (.dmg/.exe) "
                  "needs a real antivirus — this scan reads source and config.",
                  file=err)
            return None
        else:
            print(_NAME_HELP.format(arg=arg), file=err, end="")
            return None
    if archive is None:
        return None
    try:
        return extract_archive(Path(archive), tmp / "extracted")
    except (ValueError, OSError) as exc:
        # A refused extraction is itself a verdict: honest archives don't
        # need path traversal.
        print(f"tridelphi: refusing to extract {Path(archive).name}: {exc}", file=err)
        print("tridelphi: an archive built to escape its extraction directory is "
              "malicious by construction — do not install this.", file=err)
        return None


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


_grouped = grouped_lines


def _render_text(result: PreflightResult, label: str, out: TextIO) -> None:
    bar = "─" * 60
    print(bar, file=out)
    print(f"  🔺 TriDelPhi pre-install scan · {label}", file=out)
    for line in wrap(_SCOPE, 66):
        print(f"  {line}", file=out)
    print(bar, file=out)
    print("", file=out)

    by_cat: dict[str, list[PreflightFinding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)

    icon = {"fail": "🚫", "warn": "⚠️ ", "note": "🔎", "pass": "✅"}
    for letter, question, _gloss in CATEGORIES:
        group = by_cat.get(letter, [])
        crit = sum(1 for f in group if f.severity == "critical")
        warn = sum(1 for f in group if f.severity == "warning")
        if crit:
            st, note = "fail", f"{crit} to read before installing"
        elif warn:
            st, note = "warn", f"{warn} worth a look"
        elif group:
            st, note = "note", "informational"
        else:
            st, note = "pass", "nothing found"
        q = question if len(question) <= 52 else question[:51] + "…"
        print(f"  {icon[st]}  {q.ljust(52)}  {note}", file=out)
    print("", file=out)

    crits = [f for f in result.findings if f.severity == "critical"]
    if crits:
        print(f"  {'─' * 54}", file=out)
        n = len(crits)
        print(f"\n  {n} reason{'s' if n != 1 else ''} not to install this yet:\n", file=out)
        for letter, question, _gloss in CATEGORIES:
            group = [f for f in crits if f.category == letter]
            if not group:
                continue
            print(f"  🚫 {question}", file=out)
            for _sev, text, fix in _grouped(group)[:_MAX_ITEMS]:
                for i, wl in enumerate(wrap(text, 64)):
                    print(f"      {'· ' if i == 0 else '  '}{wl}", file=out)
                for fl in wrap(f"Do this: {fix}", 64):
                    print(f"        {fl}", file=out)
            print("", file=out)

    warns = [f for f in result.findings if f.severity == "warning"]
    notes = [f for f in result.findings if f.severity == "note"]
    if warns:
        print(f"  {'─' * 54}\n", file=out)
        print("  Worth a look — not proof of malice, but read these before you", file=out)
        print("  decide:\n", file=out)
        for letter, question, _gloss in CATEGORIES:
            group = [f for f in warns if f.category == letter]
            if not group:
                continue
            print(f"  ⚠️  {question}", file=out)
            for _sev, text, fix in _grouped(group)[:_MAX_ITEMS]:
                for i, wl in enumerate(wrap(text, 64)):
                    print(f"      {'· ' if i == 0 else '  '}{wl}", file=out)
                for fl in wrap(f"Do this: {fix}", 64):
                    print(f"        {fl}", file=out)
            print("", file=out)
    for _sev, text, _fix in _grouped(notes)[:_MAX_ITEMS + 4]:
        for i, wl in enumerate(wrap(text, 66)):
            print(f"  {'🔎 ' if i == 0 else '   '}{wl}", file=out)
    if notes:
        print("", file=out)

    print(f"  {'─' * 54}\n", file=out)
    if crits:
        n = len(crits)
        print(f"  Verdict:  🛑  DO NOT INSTALL THIS YET — {n} finding{'s' if n != 1 else ''} above "
              "match", file=out)
        print("            known attack shapes. Read them; if you can't explain", file=out)
        print("            one, walk away. Deleting a download costs nothing.", file=out)
    elif warns:
        print("  Verdict:  ⚠️  READ THE ITEMS ABOVE FIRST — nothing matched a known", file=out)
        print("            attack shape outright, but the flagged spots are where", file=out)
        print("            one would hide.", file=out)
    else:
        print("  Verdict:  ✅  NO KNOWN-BAD INSTALL PATTERNS FOUND.", file=out)
        print("            That is not a safety certificate: this reads source and", file=out)
        print("            config for known shapes. It cannot vouch for compiled", file=out)
        print("            binaries or what a server sends tomorrow.", file=out)
    scope = f"  Examined {result.files_examined} file{'s' if result.files_examined != 1 else ''}."
    if result.truncated:
        scope += "  ⚠️ The tree was larger than the scan cap — coverage is partial."
    print(scope + "\n", file=out)


def _render_markdown(result: PreflightResult, label: str) -> str:
    crits = [f for f in result.findings if f.severity == "critical"]
    warns = [f for f in result.findings if f.severity == "warning"]
    out: list[str] = []
    if crits:
        out.append(f"### 🔺 TriDelPhi pre-install scan — 🛑 do not install yet ({len(crits)})")
    elif warns:
        out.append("### 🔺 TriDelPhi pre-install scan — ⚠️ read before installing")
    else:
        out.append("### 🔺 TriDelPhi pre-install scan — ✅ no known-bad patterns")
    out.append(f"_{md_escape(label)} · {_SCOPE}_")
    out.append("")
    by_cat: dict[str, list[PreflightFinding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)
    out.append("| Check | Result |")
    out.append("|---|---|")
    for letter, question, _gloss in CATEGORIES:
        group = by_cat.get(letter, [])
        crit = sum(1 for f in group if f.severity == "critical")
        warn = sum(1 for f in group if f.severity == "warning")
        cell = (f"🚫 **{crit} to read first**" if crit
                else f"⚠️ {warn} worth a look" if warn
                else "🔎 informational" if group else "✅ nothing found")
        out.append(f"| {question} | {cell} |")
    out.append("")
    if crits:
        out.append("**Read these before installing:**")
        for letter, _q, _g in CATEGORIES:
            for _sev, text, fix in _grouped(
                    [f for f in crits if f.category == letter], markdown=True):
                out.append(f"- 🛑 {text} **Do this:** {fix}")
        out.append("")
    if warns:
        out.append("<details>")
        out.append(f"<summary><b>{len(warns)} worth a look</b> — tap to read</summary>")
        out.append("")
        for letter, _q, _g in CATEGORIES:
            for _sev, text, fix in _grouped(
                    [f for f in warns if f.category == letter], markdown=True)[:_MAX_ITEMS]:
                out.append(f"- ⚠️ {text} **Do this:** {fix}")
        out.append("")
        out.append("</details>")
        out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def run_scan(
    target: str,
    *,
    fmt: str = "checklist",
    sarif_file: str | None = None,
    checklist_md_file: str | None = None,
    fail_on: str = "critical",
    tool_version: str = "0",
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Scan ``target`` before it is installed. Exit 1 when a finding at or
    above ``fail_on`` exists, 0 when clean, 2 on a bad target."""
    out = out or sys.stdout
    err = err or sys.stderr

    with tempfile.TemporaryDirectory(prefix="tridelphi-scan-") as tmp:
        root = _resolve_target(target, Path(tmp), err)
        if root is None:
            return 2
        result = analyze_preflight(root, tool_version=tool_version)
        label = target if target.startswith(("npm:", "pypi:", "pip:")) \
            else (Path(target).resolve().name or target)

        if fmt in ("sarif", "json"):
            out.write(dumps(result.sarif or {"version": "2.1.0", "runs": []}))
        elif fmt == "markdown":
            out.write(_render_markdown(result, label))
        else:
            _render_text(result, label, out)

        try:
            if sarif_file and result.sarif is not None:
                atomic_write_text(sarif_file, dumps(result.sarif))
            if checklist_md_file:
                atomic_write_text(checklist_md_file, _render_markdown(result, label))
        except OSError as exc:
            print(f"tridelphi: could not write scan output: {exc}", file=err)
            return 2

    return 1 if should_fail((f.severity for f in result.findings), fail_on) else 0
