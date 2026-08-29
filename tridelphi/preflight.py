"""The pre-install trust audit — read code *before* you run its installer.

`tridelphi scan <thing>` answers the question nobody asks until the day after:
**"if I install this, what runs, and what does it reach for?"** It is built for
the attack that actually happens to people building with AI in 2026: an
assistant hands over a download link it never verified, the install command
looks legit, and the payload runs the moment `npm install` / `bash install.sh`
executes — or worse, it hides in a SKILL.md / agent config that re-runs every
time the AI loads it.

Four ideas organize the module:

1. **Install context is the severity dial.** `curl | bash` in a README is how
   half the internet installs Homebrew — worth a look, not a siren. The same
   line in an npm `postinstall`, a `.envrc`, a VS Code `folderOpen` task or a
   git hook runs *without you choosing to run it* — that is critical. Every
   discovered file carries a context (INSTALL / AGENT / DOC / CODE) and the
   detectors grade against it.

2. **Agent files are executable now.** SKILL.md, CLAUDE.md, `.cursor/rules`,
   `.claude/settings.json` hooks, `.mcp.json` servers — an assistant *acts on*
   these. A poisoned one is a dropper with a markdown extension. We look for
   the tells: instructions to act silently, download-and-run recipes,
   credential paths, imperatives hidden in HTML comments, and invisible
   Unicode (zero-width / bidi) that hides text from the human but not the
   model.

3. **Links lie by construction.** The copycat-site attack is a markdown link
   whose text says one domain and whose href goes to another. That mismatch is
   mechanical to detect, and almost never innocent.

4. **A clean result is not a safety certificate.** This is a static scan of
   source and install files for *known bad shapes*. It cannot judge a compiled
   binary, sandbox anything, or predict what a server sends tomorrow. The
   report says so, every run.

Offline by default. The two registry forms (`npm:<pkg>`, `pypi:<pkg>`) are the
explicit exceptions: they download the package (never installing or executing
it) so you can scan before the real install — and they announce the network
use before touching it.
"""

from __future__ import annotations

import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "CATEGORIES",
    "PreflightFinding",
    "PreflightResult",
    "analyze_preflight",
    "extract_archive",
]

# Categories, in report order — same contract as expose's: a plain question and
# a one-line gloss; the guided fix is per finding.
CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("I", "Does anything run the moment you install or open this?",
     "Code wired to execute automatically: npm install hooks, setup.py, .envrc, "
     "editor auto-tasks, git hooks shipped in the tree."),
    ("D", "Does the installer download and run code from the internet?",
     "Fetch-and-execute: curl|bash, PowerShell download cradles, "
     "fetch-chmod-run chains."),
    ("O", "Is anything hiding what it does?",
     "Encoded or invisible payloads: base64 piped to a shell, eval of decoded "
     "strings, zero-width and right-to-left Unicode tricks."),
    ("C", "Does anything reach for your keys, wallets, or browser data?",
     "Reads of ~/.ssh, cloud credentials, browser profile stores, crypto "
     "wallets — and whether the same file also talks to the network."),
    ("A", "Are the AI-assistant files safe to let an agent load?",
     "SKILL.md, CLAUDE.md, rules files, agent hooks and MCP configs — files an "
     "assistant treats as instructions, or executes outright."),
    ("L", "Do the links go where they say they go?",
     "Link text that names one domain while the URL goes to another, raw-IP "
     "URLs, shorteners, and throwaway file hosts used as code sources."),
)
CATEGORY_ORDER = {letter: i for i, (letter, _q, _g) in enumerate(CATEGORIES)}

_SEVERITY_RANK = {"critical": 0, "warning": 1, "note": 2}


@dataclass(frozen=True, slots=True)
class PreflightFinding:
    category: str          # "I".."L"
    rule: str              # slug, e.g. "install-hook-downloader"
    severity: str          # critical / warning / note
    where: str             # target-relative "path" or "path:line"
    message: str           # plain-English, self-contained
    fix: str               # what to actually do about it


@dataclass
class PreflightResult:
    findings: list[PreflightFinding] = field(default_factory=list)
    sarif: dict[str, Any] | None = None
    files_examined: int = 0
    truncated: bool = False  # the walk hit its cap; coverage is partial

    def gating(self) -> list[PreflightFinding]:
        return [f for f in self.findings if f.severity == "critical"]


# ---------------------------------------------------------------------------
# discovery — what kind of file is this, and in what context does it run?
# ---------------------------------------------------------------------------

# Walk caps. A scan target is untrusted by definition, so it must not be able
# to hang the scanner with a million files or a 10GB blob. Partial coverage is
# reported (`truncated`), never silent.
_MAX_FILES = 6000
_MAX_READ_BYTES = 2 * 1024 * 1024

# Unlike `expose`, node_modules is IN scope: a downloaded app bundle can carry
# a malicious dependency's postinstall right there in the tree.
_SKIP_DIRS = frozenset({".venv", "venv", "__pycache__", ".mypy_cache",
                        ".pytest_cache", ".ruff_cache", ".tox", ".idea"})

# Test suites are skipped: they do not run when a package installs, and they are
# the one place a security tool, a parser, or a fuzzer legitimately embeds attack
# strings *as data* (this very scanner's fixtures are a wall of them). Skipping
# them removes a whole class of false positive without hiding install-path
# threats — a test file that an install hook actually references is pulled back
# into the scan explicitly, escalated to install context. A payload hiding in an
# unreferenced test file only runs if the victim runs the suite, which is not the
# install this command guards.
_SKIP_DIRS_TEST = frozenset({"tests", "test", "__tests__", "spec", "e2e", "fixtures"})
_TEST_FILE = re.compile(r"(?i)(^test_|_test\.|\.test\.|\.spec\.|conftest\.py$)")

# INSTALL context: content that executes without the user deliberately running
# it — at install time, on cd, on folder-open, on git actions.
_INSTALL_NAMES = frozenset({
    "install.sh", "install.ps1", "setup.sh", "bootstrap.sh", "makefile",
    "setup.py", "setup.cfg", ".envrc",
})
# AGENT context: files an AI assistant loads as instructions or executes.
_AGENT_NAMES = frozenset({
    "skill.md", "skills.md", "claude.md", "agents.md", "agent.md",
    ".cursorrules", ".windsurfrules", "gemini.md",
    "copilot-instructions.md", ".mcp.json", "mcp.json",
})
_DOC_NAMES_PREFIX = ("readme", "install", "getting", "quickstart", "setup")

_SHELL_EXTS = (".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd")
_CODE_EXTS = (".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".pl")


@dataclass
class _File:
    path: Path
    rel: str
    context: str  # "install" | "agent" | "doc" | "code"


@dataclass
class _Surface:
    files: list[_File] = field(default_factory=list)
    package_jsons: list[Path] = field(default_factory=list)
    truncated: bool = False


def _classify(rel: Path) -> str | None:
    """The scan context for one path, or None if it is not worth reading."""
    name = rel.name.lower()
    parts = [p.lower() for p in rel.parts]
    parent = parts[:-1]
    if ".git" in parent and "hooks" in parent:
        return "install"          # a shipped git hook runs on git actions
    if ".githooks" in parent or name == ".envrc":
        return "install"
    if name in _INSTALL_NAMES:
        return "install"
    if ".vscode" in parent and name in ("tasks.json", "settings.json"):
        return "install"          # folderOpen tasks run when the folder opens
    if name in _AGENT_NAMES:
        return "agent"
    if ".claude" in parent or ".cursor" in parent or ".windsurf" in parent:
        # settings, hooks, rules — all of it steers or is executed by an agent.
        return "agent"
    if name.startswith(_DOC_NAMES_PREFIX) and rel.suffix in (".md", ".rst", ".txt"):
        return "doc"
    if rel.suffix == ".md" and len(parent) <= 1:
        return "doc"
    if name == "dockerfile" or rel.suffix in _SHELL_EXTS or rel.suffix in _CODE_EXTS:
        return "code"
    return None


def _discover(root: Path) -> _Surface:
    s = _Surface()
    stack = [root]
    seen = 0
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
                low = entry.name.lower()
                if low not in _SKIP_DIRS and low not in _SKIP_DIRS_TEST:
                    stack.append(entry)
                continue
            if not entry.is_file():
                continue
            if _TEST_FILE.search(entry.name):
                continue
            seen += 1
            if seen > _MAX_FILES:
                s.truncated = True
                return s
            rel = entry.relative_to(root)
            if entry.name == "package.json":
                s.package_jsons.append(entry)
                continue
            ctx = _classify(rel)
            if ctx is not None:
                s.files.append(_File(entry, str(rel), ctx))
    return s


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            with path.open("rb") as fh:
                return fh.read(_MAX_READ_BYTES).decode("utf-8", errors="replace")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ---------------------------------------------------------------------------
# pattern library
# ---------------------------------------------------------------------------

# Download-and-execute. These run whatever a remote server chooses to send at
# that moment — the defining shape of the copycat-installer attack.
_DOWNLOAD_EXEC: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pipes a download straight into a shell",
     re.compile(r"\b(curl|wget)\b[^|\n;&]{0,160}\|\s*(sudo\s+)?(ba|z|da)?sh\b")),
    ("substitutes a download into a shell command",
     re.compile(r"\b(ba|z)?sh\s+(-c\s+)?[\"']?\s*[<$]\(\s*(curl|wget)\b")),
    ("PowerShell download cradle",
     re.compile(r"(?i)\b(iwr|invoke-webrequest|invoke-restmethod|"
                r"downloadstring|downloadfile)\b[^\n]{0,200}\|\s*iex\b")),
    ("PowerShell executes a downloaded string",
     re.compile(r"(?i)\biex\b[^\n]{0,60}\b(iwr|invoke-webrequest|"
                r"downloadstring|net\.webclient)\b")),
    ("downloads a file, marks it executable, and runs it",
     re.compile(r"\b(curl|wget)\b[^\n]{0,200}&&[^\n]{0,80}chmod\s+\+x[^\n]{0,120}"
                r"(&&|;)[^\n]{0,40}\./")),
    ("Python downloads code and exec()s it",
     re.compile(r"\b(urlopen|requests\.get|httpx\.get)\([^\n]{0,160}\)"
                r"[^\n]{0,120}\b(exec|eval)\s*\(")),
    ("JavaScript downloads code and evaluates it",
     re.compile(r"\b(fetch|https?\.get|axios\.get)\s*\([^\n]{0,160}"
                r"[^\n]{0,120}\beval\s*\(")),
)

# Obfuscation — encoding a command has one honest use (none, at install time).
_OBFUSCATION: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decodes base64 and pipes it into a shell",
     re.compile(r"base64\s+(-d|-D|--decode)\b[^\n|]{0,80}\|\s*(sudo\s+)?(ba)?sh\b")),
    ("shell-executes an encoded string",
     re.compile(r"\becho\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|\s*base64\s+"
                r"(-d|-D|--decode)")),
    ("evaluates base64-decoded JavaScript",
     re.compile(r"\b(eval|Function)\s*\(\s*(atob\s*\(|Buffer\.from\s*\([^)]{1,200},"
                r"\s*[\"']base64)")),
    ("executes base64-decoded Python",
     re.compile(r"\b(exec|eval)\s*\(\s*(compile\s*\(\s*)?"
                r"(base64\.(b64|b32|b16)decode|codecs\.decode)")),
    ("PowerShell encoded command",
     re.compile(r"(?i)powershell[^\n]{0,80}\s-e(nc(odedcommand)?)?\s+"
                r"[A-Za-z0-9+/=]{40,}")),
    ("assembles code from character codes and evaluates it",
     re.compile(r"\beval\s*\(\s*String\.fromCharCode")),
)

# A long base64 literal is only a *warning* — sourcemaps, fonts and fixtures
# embed them legitimately — but in an install hook or agent file it deserves
# eyes before the code runs.
_LONG_B64 = re.compile(r"[\"']?[A-Za-z0-9+/]{200,}={0,2}[\"']?")

# Invisible Unicode: zero-width characters and bidirectional overrides. The
# human reads one thing, the model (or compiler) reads another. There is no
# legitimate reason for these in an agent file or a script.
_INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\u202a-\u202e\u2066-\u2069\ufeff]")

# Credential and wallet reach. Matching is deliberately path-shaped — the word
# "ssh" alone flags nothing; "~/.ssh" or expanduser('~/.aws') does.
_CRED_PATHS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("your SSH keys",
     re.compile(r"(~|\$HOME|%USERPROFILE%|expanduser\([\"']~|homedir\(\)[^\n]{0,20})"
                r"[^\n]{0,40}[/\\]\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b")),
    ("your cloud credentials",
     re.compile(r"\.aws[/\\]credentials|\.config[/\\]gcloud|\.kube[/\\]config|"
                r"\.azure[/\\](credentials|accessTokens)")),
    ("your registry / login tokens",
     re.compile(r"(~|\$HOME|%USERPROFILE%|expanduser\([\"']~)[^\n]{0,30}"
                r"[/\\]\.(npmrc|pypirc|netrc|git-credentials)\b")),
    ("your browser's saved logins or cookies",
     re.compile(r"(?i)(chrome|chromium|brave|edge|firefox|mozilla)[^\n]{0,80}"
                r"(login data|cookies|local state|key4\.db|logins\.json)")),
    ("a crypto wallet",
     re.compile(r"(?i)wallet\.dat|(exodus|electrum|metamask|phantom|ledger live)"
                r"[^\n]{0,50}(wallet|vault|seed|keystore|leveldb)")),
    ("the system keychain",
     re.compile(r"security\s+(find-(generic|internet)-password|dump-keychain)|"
                r"\bvaultcmd\b")),
    ("your environment variables, wholesale",
     re.compile(r"\b(env|printenv)\s*\|\s*(curl|wget|nc|ncat)\b|"
                r"JSON\.stringify\s*\(\s*process\.env\s*\)")),
)

# "This file also talks to the network" — the half that turns a credential
# read from odd into exfiltration.
_NETWORK_SEND = re.compile(
    r"\bcurl\b[^\n]{0,160}(\s-(d|F|T)\b|--data|--upload-file)|"
    r"\b(requests|httpx)\.post\s*\(|\burlopen\s*\([^\n]{0,120}data\s*=|"
    r"\bfetch\s*\([^\n]{0,200}(method\s*:\s*[\"'](POST|PUT)|body\s*:)|"
    r"\baxios\.(post|put)\s*\(|\bnc\s+-|\bncat\b|\bscp\b\s")

# Agent-file tells. Secrecy alone is a warning (a style guide can legitimately
# say "never reveal API keys in output"); secrecy *near* an action — download,
# execute, read credentials — is the poisoned-skill shape, and gates.
_SECRECY = re.compile(
    r"(?i)\b(silently|covertly|without\s+(telling|informing|alerting|notifying|"
    r"mentioning(\s+(this|it))?\s+to)\s+the\s+(user|human)|"
    r"do\s+not\s+(tell|mention|inform|show|reveal|disclose|alert)|"
    r"don'?t\s+(tell|mention|inform|show|reveal)|"
    r"never\s+(tell|mention|reveal|disclose)|"
    r"hide\s+(this|these|the\s+following)|keep\s+(this|it)\s+(secret|hidden)|"
    r"without\s+asking|do\s+not\s+ask\s+(for\s+)?(permission|confirmation))\b")
_AGENT_ACTION = re.compile(
    r"(?i)\b(curl|wget|iwr|invoke-webrequest|download|fetch\s+https?://|"
    r"pip\s+install|npm\s+install|npx\s+|chmod\s+\+x|base64|"
    r"\.ssh|\.aws|\.npmrc|credentials?|token|api[_\s-]?key|password)\b")
_HTML_COMMENT = re.compile(r"<!--([\s\S]{0,4000}?)-->")
_IMPERATIVE = re.compile(
    r"(?i)\b(run|execute|download|install|fetch|send|upload|read|copy|curl|"
    r"post|exfiltrate|append|write)\b")

_URL = re.compile(r"https?://[^\s\"'<>\)\]`]+")
_MD_LINK = re.compile(r"\[([^\]\n]{1,200})\]\((https?://[^)\s]+)\)")
_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)

# Link text like `ruamel.yaml`, `setup.py` or `index.js` reads as a dotted name
# but claims no domain — so a mismatch against the href is not a lie. A domain
# claim is only real when the final label is a plausible TLD, i.e. NOT one of the
# file/package/config suffixes that pepper a code project's prose.
_NOT_A_TLD = frozenset({
    "yaml", "yml", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "json", "md",
    "rst", "txt", "sh", "bash", "zsh", "ps1", "rb", "go", "rs", "java", "kt",
    "c", "cc", "cpp", "h", "hpp", "toml", "cfg", "ini", "lock", "xml", "html",
    "htm", "css", "scss", "png", "svg", "jpg", "gif", "env", "sample", "example",
    "template", "dist", "map", "d", "min", "test", "spec", "conf", "properties",
})


def _text_claims_domain(text_domain: str) -> bool:
    """Does this dotted token in link text actually claim a web domain (so a
    mismatch would be a lie), or is it a filename / package name?"""
    tld = text_domain.rsplit(".", 1)[-1].lower()
    return tld not in _NOT_A_TLD and tld.isalpha()

_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "lnkd.in",
})
# Throwaway hosts that are fine for sharing files and indefensible as the
# *source of code an installer runs*.
_THROWAWAY_HOSTS = frozenset({
    "pastebin.com", "paste.ee", "hastebin.com", "dpaste.com", "rentry.co",
    "transfer.sh", "anonfiles.com", "gofile.io", "file.io", "0x0.st",
    "catbox.moe", "litterbox.catbox.moe", "temp.sh", "cdn.discordapp.com",
})
_IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")

# npm lifecycle commands that are boring and everywhere. Exact-match by
# design: "node-gyp rebuild && curl ..." must not slip through on a prefix.
_BENIGN_LIFECYCLE = tuple(re.compile(p) for p in (
    r"^node-gyp rebuild$",
    r"^prebuild-install(\s.*)?(\|\|\s*node-gyp rebuild)?$",
    r"^husky( install)?$",
    r"^patch-package$",
    r"^opencollective(-postinstall)?( .*)?$",
    r"^electron-builder install-app-deps$",
    r"^prisma generate$",
    r"^ngcc(\s.*)?$",
))
_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")

_HOST = re.compile(r"https?://([^/\s:\"'<>]+)")


def _registrable(host: str) -> str:
    """Last two DNS labels — a deliberate approximation of the registrable
    domain. Good enough to catch `github.com` vs `github-com.download.example`;
    a PSL dependency is not worth the tree for this."""
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------

_FIX_DOWNLOADER = ("do not install this until you know exactly what that URL serves. "
                   "Fetch the file yourself, read it, then run it — never pipe a "
                   "download into a shell you didn't inspect.")
_FIX_OBFUSCATION = ("decode it yourself and read what it actually runs before "
                    "installing. Honest install scripts do not need to be encoded.")
_FIX_CRED = ("assume the worst: an installer or bundled file has no business here. "
             "Do not install; if you already ran it, rotate the affected "
             "credentials from a machine you trust.")
_FIX_AGENT = ("do not let an assistant load this file until a human has read every "
              "line of it — including HTML comments and anything invisible. Agent "
              "files are executable code wearing a markdown extension.")


def _scan_text(f: _File, text: str) -> list[PreflightFinding]:
    """Run every content detector appropriate to one file."""
    out: list[PreflightFinding] = []
    install = f.context == "install"
    agent = f.context == "agent"
    doc = f.context == "doc"

    # -- D: download-and-execute ------------------------------------------
    for label, pattern in _DOWNLOAD_EXEC:
        m = pattern.search(text)
        if not m:
            continue
        where = f"{f.rel}:{_line_of(text, m.start())}"
        snippet = " ".join(m.group(0).split())[:120]
        url_m = _URL.search(m.group(0))
        host = _HOST.match(url_m.group(0)).group(1) if url_m and _HOST.match(url_m.group(0)) else ""
        untrustworthy = bool(
            _IP_URL.search(m.group(0))
            or _registrable(host) in {_registrable(h) for h in _SHORTENERS}
            or host in _THROWAWAY_HOSTS
        )
        if install or agent or untrustworthy:
            sev = "critical"
            why = ("it runs automatically" if install else
                   "an AI assistant acts on this file" if agent else
                   "the source is a raw IP, shortener, or throwaway host")
            out.append(PreflightFinding("D", "download-and-execute", sev, where,
                f"This {label} (`{snippet}`) — and {why}, so whatever that server "
                "chooses to send gets executed without you ever seeing it.",
                _FIX_DOWNLOADER))
        else:
            out.append(PreflightFinding("D", "download-and-execute-doc", "warning", where,
                f"The install instructions {label} (`{snippet}`). Plenty of real "
                "projects do this, and it is still the exact shape of the "
                "copycat-installer attack — the server decides what you run.",
                "verify the domain character-by-character against the project's "
                "official page, then prefer downloading the script and reading it "
                "before running it."))
        break  # one finding per file per detector family keeps the report readable

    # -- O: obfuscation ----------------------------------------------------
    # A doc that *describes* `eval(atob(...))` is documentation, not a dropper —
    # so encoded execution gates in code/install/agent files and is a warning in
    # prose. (A README is still where a copycat's real payload could hide, hence
    # a warning rather than nothing.)
    for label, pattern in _OBFUSCATION:
        m = pattern.search(text)
        if m:
            where = f"{f.rel}:{_line_of(text, m.start())}"
            if doc:
                out.append(PreflightFinding("O", "encoded-execution-doc", "warning", where,
                    f"These instructions {label}. In a real installer that is a way "
                    "to stop you reading a command before it runs; in documentation "
                    "it may just be describing one.",
                    "if this is a command you are meant to run, decode it first."))
            else:
                out.append(PreflightFinding("O", "encoded-execution", "critical", where,
                    f"This file {label}. Encoding a command has exactly one purpose: "
                    "stopping you from reading it before it runs.", _FIX_OBFUSCATION))
            break
    if (install or agent) and "encoded-execution" not in {x.rule for x in out}:
        m = _LONG_B64.search(text)
        if m:
            where = f"{f.rel}:{_line_of(text, m.start())}"
            out.append(PreflightFinding("O", "opaque-blob", "warning", where,
                "A long base64 blob sits in a file that runs automatically (or "
                "that an assistant loads). It may be an embedded asset — or a "
                "payload. You cannot tell without decoding it.",
                "decode the blob and look at it before installing."))

    # -- O: invisible unicode ---------------------------------------------
    probe = text[1:] if text[:1] == "\ufeff" else text  # a leading BOM is honest
    m = _INVISIBLE.search(probe)
    if m and (agent or install or f.context == "code"):
        ch = f"U+{ord(m.group(0)):04X}"
        where = f"{f.rel}:{_line_of(probe, m.start())}"
        out.append(PreflightFinding("O", "invisible-characters", "critical", where,
            f"Invisible Unicode ({ch}, zero-width or bidirectional control) is "
            "embedded here. You read one thing; a model or interpreter reads "
            "another. There is no honest reason for this in a "
            f"{'script' if not agent else 'file an assistant loads'}.",
            "open the file in an editor that shows invisible characters (or run "
            "`grep -P '[\\x{200b}-\\x{200d}\\x{202a}-\\x{202e}]'`) and read what "
            "is actually there before letting anything load it."))

    # -- C: credential reach ----------------------------------------------
    sends = bool(_NETWORK_SEND.search(text))
    for label, pattern in _CRED_PATHS:
        m = pattern.search(text)
        if not m:
            continue
        where = f"{f.rel}:{_line_of(text, m.start())}"
        if install or agent or sends:
            reason = ("and this file also sends data over the network — that pairing "
                      "is exfiltration's exact shape" if sends else
                      "inside a file that runs automatically at install time" if install
                      else "inside a file an AI assistant acts on")
            out.append(PreflightFinding("C", "credential-reach", "critical", where,
                f"This file reaches for {label} — {reason}.", _FIX_CRED))
        else:
            out.append(PreflightFinding("C", "credential-reach-code", "warning", where,
                f"This file references {label}. Some tools have a reason (a backup "
                "utility, an SSH client); most don't. Worth knowing before you "
                "install.", "check whether this app has any business touching "
                "that path; if you can't see why, don't install it."))
        break

    # -- A: agent-file tells ----------------------------------------------
    if agent:
        sec = _SECRECY.search(text)
        if sec:
            near = text[max(0, sec.start() - 300): sec.end() + 300]
            where = f"{f.rel}:{_line_of(text, sec.start())}"
            if _AGENT_ACTION.search(near):
                out.append(PreflightFinding("A", "covert-instruction", "critical", where,
                    "This agent file pairs a secrecy instruction "
                    f"(“{' '.join(sec.group(0).split())}”) with an action — download, "
                    "install, or credential access. That is the poisoned-skill "
                    "shape: the assistant is being told to act and not tell you.",
                    _FIX_AGENT))
            else:
                out.append(PreflightFinding("A", "secrecy-language", "warning", where,
                    "This agent file tells the assistant to keep something from "
                    f"you (“{' '.join(sec.group(0).split())}”). It may be innocent "
                    "phrasing — but an instruction file has no business asking for "
                    "silence.", "read the surrounding paragraph and decide whether "
                    "you'd have written it."))
        for m in _HTML_COMMENT.finditer(text):
            body = m.group(1)
            if _IMPERATIVE.search(body) and (_URL.search(body) or
                                             _AGENT_ACTION.search(body)):
                where = f"{f.rel}:{_line_of(text, m.start())}"
                out.append(PreflightFinding("A", "hidden-comment-instruction",
                    "critical", where,
                    "An HTML comment in this agent file carries instructions — "
                    "invisible in any rendered view, but a model reads it like any "
                    "other text. Rendered-invisible imperatives are how a poisoned "
                    "file passes a human skim.", _FIX_AGENT))
                break

    # -- L: link honesty ---------------------------------------------------
    if agent or doc or install:
        for m in _MD_LINK.finditer(text):
            label_text, href = m.group(1), m.group(2)
            dom = _DOMAIN_IN_TEXT.search(label_text)
            if not dom or not _text_claims_domain(dom.group(1)):
                continue
            href_host = _HOST.match(href)
            if not href_host:
                continue
            if _registrable(dom.group(1)) != _registrable(href_host.group(1)):
                where = f"{f.rel}:{_line_of(text, m.start())}"
                out.append(PreflightFinding("L", "link-text-mismatch", "critical", where,
                    f"A link's text says `{dom.group(1)}` but it actually goes to "
                    f"`{href_host.group(1)}`. This is the copycat-site trick: you "
                    "read the trusted name and click the attacker's server.",
                    "trust the href, never the text — and don't follow this one "
                    "until you know why it lies."))
                break
        for m in _URL.finditer(text):
            host_m = _HOST.match(m.group(0))
            if not host_m:
                continue
            host = host_m.group(1).lower().rstrip(".")
            where = f"{f.rel}:{_line_of(text, m.start())}"
            if host in _SHORTENERS:
                out.append(PreflightFinding("L", "shortened-link", "warning", where,
                    f"A shortened link ({host}) hides its destination. In install "
                    "instructions that is a choice, and not a reassuring one.",
                    "expand the link (curl -sIL) and check the real destination "
                    "before touching it."))
                break
            if host in _THROWAWAY_HOSTS and f.context in ("install", "code"):
                out.append(PreflightFinding("L", "throwaway-code-host", "critical", where,
                    f"Code is being fetched from a throwaway file host ({host}). "
                    "Legitimate software does not distribute itself from paste "
                    "sites or chat CDNs.", _FIX_DOWNLOADER))
                break
            if _IP_URL.match(m.group(0)):
                out.append(PreflightFinding("L", "raw-ip-url", "warning", where,
                    f"A URL points at a bare IP address ({m.group(0)[:40]}…). No "
                    "domain means no name to verify and no certificate identity "
                    "worth the name.", "find out whose server that is before "
                    "anything fetches from it."))
                break
            if "xn--" in host or not host.isascii():
                out.append(PreflightFinding("L", "lookalike-domain", "warning", where,
                    f"This domain ({host}) uses punycode or non-ASCII characters — "
                    "the raw material of look-alike domains.",
                    "compare it character-by-character with the domain you meant."))
                break

    return out


# ---------------------------------------------------------------------------
# structured files: package.json, agent hooks/MCP, VS Code tasks, git hooks
# ---------------------------------------------------------------------------

_SUSPICIOUS_CMD = re.compile(
    r"(?i)\b(curl|wget|iwr|invoke-webrequest|base64|"
    r"powershell\b[^\n]{0,60}-e(nc)?\b|nc\s+-|\bncat\b)\b")


def _scan_package_json(path: Path, root: Path) -> tuple[list[PreflightFinding], list[Path]]:
    """npm lifecycle scripts: the single most-used malware delivery slot in the
    JS ecosystem. Returns findings plus referenced script files to pull into
    the INSTALL-context scan set."""
    out: list[PreflightFinding] = []
    extra: list[Path] = []
    raw = _read_text(path)
    if raw is None:
        return out, extra
    try:
        doc = json.loads(raw)
    except ValueError:
        return out, extra
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return out, extra
    rel = str(path.relative_to(root))
    for key in _LIFECYCLE_KEYS:
        cmd = scripts.get(key)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        cmd = cmd.strip()
        line = raw.count("\n", 0, raw.find(f'"{key}"')) + 1 if f'"{key}"' in raw else 1
        where = f"{rel}:{line}"
        if any(p.match(cmd) for p in _BENIGN_LIFECYCLE):
            continue
        if _SUSPICIOUS_CMD.search(cmd) or _OBFUSCATION[0][1].search(cmd) or \
                any(p.search(cmd) for _l, p in _DOWNLOAD_EXEC):
            out.append(PreflightFinding("I", "install-hook-downloader", "critical", where,
                f"`{key}` runs `{cmd[:140]}` the moment this package installs — "
                "before you have run anything yourself. It reaches for the network "
                "or an encoder, which is the npm-malware delivery shape.",
                "do not install. If you need this package, pin an audited version "
                "and use --ignore-scripts."))
            continue
        # A plain lifecycle command still deserves eyes — show it, and follow a
        # referenced local script into the install-context scan.
        out.append(PreflightFinding("I", "install-hook", "note", where,
            f"This package runs code at install time: `{key}: {cmd[:140]}`. "
            "Most are build steps; all deserve one read before you install.",
            "read the command (and any script it calls) before installing, or "
            "install with --ignore-scripts and run the build yourself."))
        for token in cmd.split():
            if token.endswith((".js", ".mjs", ".cjs", ".sh", ".py")):
                candidate = (path.parent / token).resolve()
                try:
                    candidate.relative_to(root.resolve())
                except ValueError:
                    continue
                if candidate.is_file():
                    extra.append(candidate)
    return out, extra


_STRUCTURED_CONFIG_NAMES = frozenset({
    ".mcp.json", "mcp.json", "settings.json", "settings.local.json",
    "tasks.json", "hooks.json",
})


def _is_structured_config(rel: str) -> bool:
    return Path(rel).name.lower() in _STRUCTURED_CONFIG_NAMES


def _scan_agent_configs(f: _File, text: str) -> list[PreflightFinding]:
    """Hooks and MCP servers: JSON that *is* a command line. Every command is
    surfaced; suspicious ones gate. Runs for these filenames in any context —
    a `.vscode/tasks.json` is 'install' context, an `.mcp.json` is 'agent', and
    both are command lines wearing a config extension."""
    out: list[PreflightFinding] = []
    name = Path(f.rel).name.lower()
    if not _is_structured_config(rel=f.rel):
        return out
    try:
        doc = json.loads(text)
    except ValueError:
        return out

    def commands(node: Any) -> list[str]:
        found: list[str] = []
        if isinstance(node, dict):
            cmd = node.get("command")
            if isinstance(cmd, str):
                args = node.get("args")
                joined = cmd + " " + " ".join(map(str, args)) if isinstance(args, list) else cmd
                found.append(joined)
            for v in node.values():
                found.extend(commands(v))
        elif isinstance(node, list):
            for v in node:
                found.extend(commands(v))
        return found

    is_tasks = name == "tasks.json"
    auto_open = is_tasks and '"folderOpen"' in text
    for cmd in commands(doc):
        cmd_short = " ".join(cmd.split())[:140]
        if _SUSPICIOUS_CMD.search(cmd) or any(p.search(cmd) for _l, p in _DOWNLOAD_EXEC):
            out.append(PreflightFinding("A", "agent-config-downloader", "critical", f.rel,
                f"A command in `{Path(f.rel).name}` reaches for the network or an "
                f"encoder: `{cmd_short}`. "
                + ("It runs the moment the folder opens in the editor."
                   if auto_open else
                   "It runs automatically when an assistant or editor loads this "
                   "config."), _FIX_AGENT))
        elif is_tasks and auto_open:
            out.append(PreflightFinding("A", "editor-autorun-task", "warning", f.rel,
                f"A VS Code task here runs on `folderOpen`: `{cmd_short}`. Opening "
                "the folder is enough to execute it — no install step required.",
                "read the task before opening this folder in an editor, or open "
                "with tasks disabled."))
        else:
            out.append(PreflightFinding("A", "agent-config-command", "note", f.rel,
                f"`{Path(f.rel).name}` configures a command that runs when an "
                f"assistant session or editor loads it: `{cmd_short}`.",
                "read it — this executes without a separate install step."))
    return out


def _scan_presence(f: _File) -> list[PreflightFinding]:
    """Some files matter by existing at all."""
    out: list[PreflightFinding] = []
    name = Path(f.rel).name.lower()
    parts = [p.lower() for p in Path(f.rel).parts]
    if name == ".envrc":
        out.append(PreflightFinding("I", "direnv-autorun", "note", f.rel,
            "A `.envrc` is here: with direnv enabled, it executes automatically "
            "when you cd into this directory.",
            "read it before you cd in with direnv active."))
    if ".git" in parts and "hooks" in parts and not name.endswith(".sample"):
        out.append(PreflightFinding("I", "shipped-git-hook", "warning", f.rel,
            "This tree ships a live git hook. A normal clone never carries one — "
            "hooks are not part of a repository's content — so someone put it in "
            "this archive on purpose. It runs on ordinary git commands.",
            "read the hook, and prefer deleting .git/hooks from anything you "
            "downloaded as an archive."))
    return out


# ---------------------------------------------------------------------------
# archives — scanning the tarball is the point: before install, not after
# ---------------------------------------------------------------------------

_MAX_EXTRACT_BYTES = 300 * 1024 * 1024
_MAX_EXTRACT_ENTRIES = 20000


def extract_archive(archive: Path, dest: Path) -> Path:
    """Safely extract a .tgz/.tar.gz/.tar/.zip/.whl into ``dest`` and return
    the extraction root. Path-traversal entries, links pointing outside, and
    oversize archives are refused — the target is untrusted by definition."""
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    total = 0
    if name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_EXTRACT_ENTRIES:
                raise ValueError(f"archive has {len(infos)} entries (cap {_MAX_EXTRACT_ENTRIES})")
            for info in infos:
                target = (dest / info.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    raise ValueError(f"archive entry escapes the extraction dir: {info.filename}")
                total += info.file_size
                if total > _MAX_EXTRACT_BYTES:
                    raise ValueError("archive expands past the size cap")
            zf.extractall(dest)
    elif name.endswith((".tgz", ".tar.gz", ".tar", ".tar.bz2", ".tar.xz")):
        with tarfile.open(archive) as tf:
            members = tf.getmembers()
            if len(members) > _MAX_EXTRACT_ENTRIES:
                raise ValueError(f"archive has {len(members)} entries (cap {_MAX_EXTRACT_ENTRIES})")
            for m in members:
                total += max(m.size, 0)
                if total > _MAX_EXTRACT_BYTES:
                    raise ValueError("archive expands past the size cap")
            try:
                tf.extractall(dest, filter="data")  # rejects traversal/links/devices
            except TypeError:  # pragma: no cover — pre-3.11.4 fallback
                for m in members:
                    target = (dest / m.name).resolve()
                    if not str(target).startswith(str(dest.resolve())):
                        raise ValueError(f"archive entry escapes the extraction dir: {m.name}") from None
                    if not (m.isreg() or m.isdir()):
                        raise ValueError(f"archive entry is not a plain file/dir: {m.name}") from None
                tf.extractall(dest)
            except tarfile.FilterError as exc:
                # The `data` filter refused an entry (path traversal, an absolute
                # path, a link or device). That refusal IS the finding — normalize
                # it to the ValueError this function documents so a caller sees a
                # verdict, not a traceback.
                raise ValueError(f"unsafe archive entry refused: {exc}") from None
    else:
        raise ValueError(f"unsupported archive type: {archive.name}")
    # npm tarballs wrap everything in package/; a single top dir is the root.
    entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else dest


# ---------------------------------------------------------------------------
# SARIF + entry point
# ---------------------------------------------------------------------------

_SEV_TO_LEVEL = {"critical": "error", "warning": "warning", "note": "note"}
_HELP_URI = "https://girnarholdings.github.io/TriDelPhi/"


def _to_sarif(findings: list[PreflightFinding], tool_version: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for f in sorted(findings, key=lambda x: (x.where, x.rule, x.message)):
        rule_id = f"tridelphi-scan/{f.rule}"
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({"id": rule_id, "name": f.rule.replace("-", ""),
                          "shortDescription": {"text": f"Pre-install audit: {f.rule}"},
                          "helpUri": _HELP_URI})
        path, _sep, line = f.where.partition(":")
        region = {"startLine": int(line)} if line.isdigit() else {"startLine": 1}
        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path or "README.md"},
                "region": region}}],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{"tool": {"driver": {
            "name": "tridelphi-scan", "version": tool_version,
            "informationUri": _HELP_URI, "rules": rules}},
            "results": results}],
    }


def analyze_preflight(root: str | Path, *, tool_version: str = "0") -> PreflightResult:
    """Audit ``root`` — an extracted package, cloned repo, or downloaded app —
    for install-time execution, droppers, obfuscation, credential reach,
    poisoned agent files, and dishonest links. Pure file reads; no subprocess,
    no network."""
    root = Path(root)
    surface = _discover(root)

    findings: list[PreflightFinding] = []
    extra_install: list[Path] = []
    for pkg in surface.package_jsons:
        pkg_findings, refs = _scan_package_json(pkg, root)
        findings.extend(pkg_findings)
        extra_install.extend(refs)

    scan_set = {f.path: f for f in surface.files}
    for path in extra_install:
        rel = str(path.relative_to(root.resolve())) if path.is_absolute() else str(path)
        scan_set[path] = _File(path, rel, "install")  # escalate: it runs at install

    examined = 0
    for f in scan_set.values():
        text = _read_text(f.path)
        if text is None:
            continue
        examined += 1
        findings.extend(_scan_presence(f))
        # Structured config (tasks.json, .mcp.json, hooks/settings) is scanned by
        # the JSON-aware detector, which parses commands out of the structure and
        # knows *why* they auto-run (folderOpen, session load). It supersedes the
        # generic text scan for these files — running both would double-report the
        # same command under two rules. Everything else gets the text detectors.
        structured = _scan_agent_configs(f, text)
        if structured or _is_structured_config(f.rel):
            findings.extend(structured)
        else:
            findings.extend(_scan_text(f, text))

    # Exact duplicates (same rule at the same spot) collapse.
    unique: dict[tuple[str, str], PreflightFinding] = {}
    for f in findings:
        unique.setdefault((f.rule, f.where), f)
    ordered = sorted(unique.values(),
                     key=lambda f: (CATEGORY_ORDER.get(f.category, 9),
                                    _SEVERITY_RANK.get(f.severity, 3), f.where, f.rule))
    return PreflightResult(
        findings=ordered,
        sarif=_to_sarif(ordered, tool_version),
        files_examined=examined + len(surface.package_jsons),
        truncated=surface.truncated,
    )
