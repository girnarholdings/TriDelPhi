"""Lawsuit traps in what you are about to ship.

`tridelphi launch` answers "what lawsuit traps am I about to ship?" It reads
files on disk and matches the patterns in ``data/launch_rules.yml``. It does
not call the network, it does not decide that a statute applies, and a clean
result is not a compliance certificate.

High-confidence patterns are warnings. Anything code cannot prove is a
checklist note (or a high-severity checklist warning, for health and bank
forms). False negatives are preferred: a login page, a password-reset email,
a self-hosted font, and a library with no website stay quiet.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .expose import ExposureCoverage, ExposureLimits, _read_text, _walk
from .sarif import simple_sarif
from .severity import SEVERITY_ORDER

__all__ = [
    "CATEGORIES",
    "NOT_LEGAL_ADVICE",
    "LaunchFinding",
    "LaunchResult",
    "analyze_launch",
    "load_launch_rules",
]

_HELP_URI = "https://github.com/girnarholdings/TriDelPhi/blob/main/docs/LAUNCH_RULES.md"

_STYLE_EXTS = frozenset({".css", ".scss", ".less"})
_MARKUP_EXTS = frozenset({
    ".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".mdx",
    ".php", ".erb", ".ejs", ".liquid", ".hbs", ".njk", ".mjml",
})
_SCRIPT_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts"})
_CODE_EXTS = _SCRIPT_EXTS | frozenset({".py", ".rb", ".go", ".php"})
_MD_EXTS = frozenset({".md", ".mdx"})
_READ_EXTS = _STYLE_EXTS | _MARKUP_EXTS | _SCRIPT_EXTS | _CODE_EXTS | _MD_EXTS | frozenset({".txt", ".json", ".yml", ".yaml"})

_SKIP_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "composer.lock", "cargo.lock", "poetry.lock", "gemfile.lock",
})
_SKIP_PARTS = frozenset({
    "tests", "test", "__tests__", "spec", "testing", "__snapshots__",
    "node_modules", ".git",
})

_EMAIL_PATH = re.compile(r"(?i)(^|/)(emails?|mailers?|newsletters?|campaigns?)(/|$)")
_EMAIL_NAME = re.compile(r"(?i)(newsletter|campaign)")
_SIGNUP_PATH = re.compile(r"(?i)(sign[-_ ]?up|register|create[-_ ]account|onboarding)")
_CREATE_ACCOUNT = re.compile(r"(?i)create (?:your|an) account")
_PASSWORD = re.compile(r"(?i)type=[\"']password[\"']|name=[\"']password[\"']|type=\{[\"']password[\"']\}")
_AGE_WORD = re.compile(r"(?i)(?<![a-z])(?:\bdob\b|\bage\b)(?![a-z])")
_PRICE = re.compile(
    r"(?i)(\$\s?\d|\bper\s+(?:month|year|week)\b|/mo\b|billed\s+(?:monthly|annually|yearly))"
)
_CTA = re.compile(r"(?i)\b(?:subscribe|start(?:\s+your)?\s+(?:free\s+)?trial|upgrade|start subscription)\b")
_PLAN = re.compile(r"(?i)\b(?:subscription|membership|per month|per year|/mo\b|billed monthly|pro plan)\b")
_POSTAL = re.compile(
    r"(?i)(\b\d{1,6}\s+[A-Za-z0-9][A-Za-z0-9.'-]*(?:\s+[A-Za-z0-9.'-]+){0,4}\s+"
    r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|way|court|ct|place|pl)\b"
    r"|\bp\.?\s*o\.?\s*box\s+\d+"
    r"|\{\{[^}]{0,40}(?:address|postal)[^}]{0,20}\}\})"
)
_UNSUB = re.compile(r"(?i)unsubscri|opt[- ]out|email preferences")
_PRIVACY_PATH = re.compile(r"(?i)(?:^|/)privacy(?:[-_]policy)?(?:[._/-]|$)")
_TERMS_PATH = re.compile(
    r"(?i)(?:^|/)(?:terms(?:-of-service|_of_service)?|tos)(?:[._/-]|$)|terms-of-service|terms_of_service"
)
_DMCA_PATH = re.compile(r"(?i)(?:^|/)(?:dmca|copyright-agent|designated-agent)(?:[._/-]|$)")
_PRIVACY_LINK = re.compile(r"(?i)privacy[-_ ]policy|/privacy\b|href=[\"'][^\"']*privacy")
_TERMS_LINK = re.compile(r"(?i)terms of service|terms-of-service|/terms\b|href=[\"'][^\"']*terms")
_DMCA_LINK = re.compile(r"(?i)/dmca\b|designated agent|dmca agent|copyright\.gov/dmca")
_UI_SCRIPT = re.compile(r"(?i)(<form\b|createRoot\b|react-dom|document\.body|dangerouslySetInnerHTML)")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_IMG = re.compile(r"(?i)<img\b")
_ALT = re.compile(r"(?i)\balt\s*=")
_LANDMARK = re.compile(r"(?i)(<main\b|<nav\b|role=[\"'](?:main|navigation)[\"'])")


@dataclass(frozen=True, slots=True)
class LaunchFinding:
    category: str
    rule: str
    severity: str
    where: str
    message: str
    fix: str
    kind: str = "static"


@dataclass
class LaunchResult:
    findings: list[LaunchFinding] = field(default_factory=list)
    sarif: dict[str, Any] | None = None
    coverage: ExposureCoverage = field(default_factory=ExposureCoverage)

    def warnings(self) -> list[LaunchFinding]:
        return [f for f in self.findings if f.severity == "warning"]


@dataclass(frozen=True, slots=True)
class _Doc:
    rel: str
    ext: str
    text: str
    lower: str
    raw_lower: str
    email: bool
    markup: bool
    script_ui: bool

    @property
    def page(self) -> bool:
        """A visitor-facing page, not a marketing-email template."""
        if self.email:
            return False
        return self.markup or self.script_ui


def _categories_from(rules: dict[str, Any]) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (str(row["id"]), str(row["question"]), str(row["gloss"]))
        for row in rules["categories"]
    )


@lru_cache(maxsize=1)
def load_launch_rules() -> dict[str, Any]:
    """The bundled rule table. Cached; the file ships inside the package."""
    yaml = YAML(typ="rt")
    text = resources.files(f"{__package__}.data").joinpath("launch_rules.yml").read_text("utf-8")
    loaded = yaml.load(text)
    if not isinstance(loaded, dict):
        raise ValueError("launch_rules.yml did not parse as a mapping")
    return loaded


def _rules() -> dict[str, Any]:
    return load_launch_rules()


def _rule_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rules["rules"]}


def _phrases(rules: dict[str, Any], key: str) -> tuple[str, ...]:
    return tuple(str(item).lower() for item in (rules.get(key) or ()))


def _fill(template: str, **tokens: str) -> str:
    text = str(template)
    for key, value in tokens.items():
        text = text.replace("{" + key + "}", value)
    return " ".join(text.split())


# Resolved once at import so the report and the tests share one sentence.
NOT_LEGAL_ADVICE = _fill(str(_rules()["scope"]))
CATEGORIES = _categories_from(_rules())
CATEGORY_ORDER = {letter: index for index, (letter, _question, _gloss) in enumerate(CATEGORIES)}


def _finding(rules: dict[str, Any], rule_id: str, where: str, **tokens: str) -> LaunchFinding:
    spec = _rule_index(rules)[rule_id]
    kind = str(spec.get("kind") or "static")
    message = _fill(str(spec["message"]), **tokens)
    if kind == "checklist" and not message.lower().startswith(("checklist", "high-severity checklist")):
        message = f"Checklist: {message}"
    return LaunchFinding(
        category=str(spec["category"]),
        rule=rule_id,
        severity=str(spec["severity"]),
        where=where,
        message=message,
        fix=_fill(str(spec["fix"]), **tokens),
        kind=kind,
    )


def _line_of(text: str, needle: str) -> int:
    index = text.lower().find(needle.lower())
    if index < 0:
        return 1
    return text.count("\n", 0, index) + 1


def _where(doc: _Doc, needle: str = "") -> str:
    line = _line_of(doc.text, needle) if needle else 1
    return f"{doc.rel}:{line}"


def _has_phrase(lower: str, phrases: tuple[str, ...]) -> str | None:
    """Literal phrase match. Short single words use boundaries so ``offer`` does
    not fire inside ``offering`` and ``dob`` is not this function's job."""
    for phrase in phrases:
        if not phrase:
            continue
        bounded = (
            phrase[0].isalnum()
            and phrase[-1].isalnum()
            and " " not in phrase
            and len(phrase) <= 16
            and "." not in phrase
            and "/" not in phrase
        )
        if bounded:
            if re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", lower):
                return phrase
        elif phrase in lower:
            return phrase
    return None


def _strip_comments(text: str) -> str:
    return _BLOCK_COMMENT.sub(" ", _HTML_COMMENT.sub(" ", text))


def _is_skipped_rel(rel: Path) -> bool:
    name = rel.name.lower()
    return (
        name in _SKIP_NAMES
        or any(part.lower() in _SKIP_PARTS for part in rel.parts)
        or ".test." in name
        or ".spec." in name
        or ".stories." in name
    )


def _emailish(rel: Path) -> bool:
    posix = rel.as_posix()
    return bool(_EMAIL_PATH.search(posix) or _EMAIL_NAME.search(rel.name))


def _load_docs(
    root: Path, files: list[Path], coverage: ExposureCoverage, cap: int,
) -> list[_Doc]:
    docs: list[_Doc] = []
    for path in files:
        if coverage.deadline and time.monotonic() > coverage.deadline:
            coverage.mark_incomplete("launch analysis exceeded its time budget")
            break
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if _is_skipped_rel(rel):
            continue
        ext = rel.suffix.lower()
        if ext not in _READ_EXTS:
            continue
        raw = _read_text(path, cap, coverage=coverage)
        if raw is None:
            continue
        text = _strip_comments(raw)
        script_ui = ext in _SCRIPT_EXTS and bool(_UI_SCRIPT.search(text))
        docs.append(_Doc(
            rel=rel.as_posix(),
            ext=ext,
            text=text,
            lower=text.lower(),
            # License headers live in block comments. Other detectors see the
            # stripped text so a commented-out font URL does not fire.
            raw_lower=raw.lower(),
            email=_emailish(rel),
            markup=ext in _MARKUP_EXTS,
            script_ui=script_ui,
        ))
    return docs


def _pages(docs: list[_Doc]) -> list[_Doc]:
    return [doc for doc in docs if doc.page]


def _site_anchor(pages: list[_Doc]) -> _Doc:
    """Prefer the primary page over the alphabetically first template."""
    for doc in pages:
        if Path(doc.rel).stem.lower() in {"index", "home", "app", "layout", "page"}:
            return doc
    return pages[0]


def _surface(docs: list[_Doc]) -> list[_Doc]:
    """Markup, styles, and scripts — not markdown essays or lockfiles."""
    return [
        doc for doc in docs
        if doc.markup or doc.ext in _STYLE_EXTS or doc.ext in _SCRIPT_EXTS or doc.ext in _CODE_EXTS
    ]


def _detect_coppa(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    phrases = _phrases(rules, "coppa_age_phrases")
    out: list[LaunchFinding] = []
    for doc in docs:
        if doc.email or doc.ext in _MD_EXTS | _STYLE_EXTS:
            continue
        if not (doc.markup or doc.script_ui or doc.ext in _SCRIPT_EXTS):
            continue
        path_signup = bool(_SIGNUP_PATH.search(doc.rel))
        create = bool(_CREATE_ACCOUNT.search(doc.text))
        if not _PASSWORD.search(doc.text):
            continue
        if not (path_signup or create):
            continue
        if _has_phrase(doc.lower, phrases) or _AGE_WORD.search(doc.text):
            continue
        out.append(_finding(rules, "coppa-age-gate", _where(doc, "password"), detail=doc.rel))
        break
    return out


def _detect_fonts(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    hosts = tuple(str(host).lower() for host in (rules.get("fonts") or {}).get("hosts") or ())
    found: list[tuple[_Doc, str]] = []
    seen: set[str] = set()
    for doc in docs:
        if doc.ext in _MD_EXTS or doc.ext in {".py", ".rb", ".go", ".json", ".yml", ".yaml", ".txt"}:
            continue
        if not (doc.markup or doc.ext in _STYLE_EXTS or doc.ext in _SCRIPT_EXTS):
            continue
        for host in hosts:
            if host in doc.lower and host not in seen:
                seen.add(host)
                found.append((doc, host))
    if not found:
        return []
    host_list = ", ".join(host for _doc, host in found)
    return [_finding(
        rules, "third-party-font", _where(found[0][0], found[0][1]),
        detail=found[0][0].rel, hosts=host_list,
    )]


def _vendor_hits(docs: list[_Doc], vendors: list[Any]) -> list[tuple[str, str, _Doc, str]]:
    hits: list[tuple[str, str, _Doc, str]] = []
    seen: set[str] = set()
    for vendor in vendors:
        label = str(vendor["label"])
        vid = str(vendor["id"])
        snippets = tuple(str(item).lower() for item in vendor.get("snippets") or ())
        for doc in docs:
            if not (doc.markup or doc.ext in _SCRIPT_EXTS or doc.ext in _STYLE_EXTS):
                continue
            snippet = _has_phrase(doc.lower, snippets)
            if snippet and vid not in seen:
                seen.add(vid)
                hits.append((vid, label, doc, snippet))
                break
    return hits


def _repo_has(docs: list[_Doc], phrases: tuple[str, ...]) -> bool:
    return any(_has_phrase(doc.lower, phrases) for doc in docs)


def _detect_replay(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    consent = _phrases(rules, "recording_consent")
    mask = _phrases(rules, "recording_mask")
    has_consent = _repo_has(docs, consent)
    has_mask = _repo_has(docs, mask)
    out: list[LaunchFinding] = []
    for _vid, label, doc, snippet in _vendor_hits(docs, list(rules.get("session_replay") or [])):
        if not has_consent:
            out.append(_finding(
                rules, "session-replay", _where(doc, snippet), detail=doc.rel, vendor=label,
            ))
        elif not has_mask:
            out.append(_finding(
                rules, "session-replay-unmasked", _where(doc, snippet), detail=doc.rel, vendor=label,
            ))
    posthog = rules.get("posthog") or {}
    present = tuple(str(item).lower() for item in posthog.get("present") or ())
    on = tuple(str(item).lower() for item in posthog.get("recording_on") or ())
    off = tuple(str(item).lower() for item in posthog.get("recording_off") or ())
    posthog_doc: _Doc | None = None
    posthog_snippet = ""
    recording = False
    disabled = False
    present_doc: _Doc | None = None
    present_snippet = ""
    for doc in docs:
        if doc.ext in _MD_EXTS:
            continue
        # `disable_session_recording: true` contains the substring
        # `session_recording: true`. An explicit off wins inside that file.
        file_off = _has_phrase(doc.lower, off) is not None
        started = "startsessionrecording" in doc.lower
        if file_off:
            disabled = True
        if started or (not file_off and (snippet := _has_phrase(doc.lower, on))):
            recording = True
            posthog_doc = posthog_doc or doc
            posthog_snippet = posthog_snippet or (snippet if not started else "startsessionrecording")
        elif (snippet := _has_phrase(doc.lower, present)):
            present_doc = present_doc or doc
            present_snippet = present_snippet or snippet
    if posthog_doc is None and not recording:
        posthog_doc = present_doc
        posthog_snippet = present_snippet
    if posthog_doc is not None and recording:
        if not has_consent:
            out.append(_finding(
                rules, "session-replay", _where(posthog_doc, posthog_snippet),
                detail=posthog_doc.rel, vendor="PostHog session recording",
            ))
        elif not has_mask:
            out.append(_finding(
                rules, "session-replay-unmasked", _where(posthog_doc, posthog_snippet),
                detail=posthog_doc.rel, vendor="PostHog session recording",
            ))
    elif posthog_doc is not None and not disabled:
        out.append(_finding(
            rules, "posthog-replay-default", _where(posthog_doc, posthog_snippet),
            detail=posthog_doc.rel,
        ))
    return out


def _detect_canspam(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    marketing = _phrases(rules, "email_marketing_phrases")
    transactional = _phrases(rules, "email_transactional_phrases")
    for doc in docs:
        if not doc.email:
            continue
        if doc.ext not in _MARKUP_EXTS | {".txt"}:
            continue
        is_marketing = _has_phrase(doc.lower, marketing) is not None
        is_transactional = _has_phrase(doc.lower, transactional) is not None
        # A password reset with no promotion stays quiet. A promotion that
        # also says "reset your password" still needs the footer.
        if is_transactional and not is_marketing:
            continue
        if not is_marketing:
            continue
        missing: list[str] = []
        if not _UNSUB.search(doc.text):
            missing.append("an unsubscribe link")
        if not _POSTAL.search(doc.text):
            missing.append("a physical postal address")
        if not missing:
            continue
        return [_finding(
            rules, "can-spam-footer", _where(doc),
            detail=doc.rel, missing=" and ".join(missing),
        )]
    return []


def _detect_renewal(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    renewal = _phrases(rules, "renewal_phrases")
    for doc in docs:
        if doc.email or doc.ext in _MD_EXTS | _STYLE_EXTS:
            continue
        if not (doc.markup or doc.script_ui or doc.ext in _SCRIPT_EXTS):
            continue
        has_cta = bool(_CTA.search(doc.text))
        has_price = bool(_PRICE.search(doc.text))
        has_plan = bool(_PLAN.search(doc.text))
        has_renewal = _has_phrase(doc.lower, renewal) is not None
        if has_renewal:
            continue
        if has_cta and has_price:
            return [_finding(rules, "auto-renewal-terms", _where(doc, "subscribe"), detail=doc.rel)]
        if has_cta and has_plan:
            return [_finding(rules, "auto-renewal-review", _where(doc), detail=doc.rel)]
    return []


def _policy_empty(text: str) -> bool:
    plain = " ".join(re.sub(r"<[^>]+>", " ", text).split())
    if len(plain) < 40:
        return True
    return bool(re.fullmatch(
        r"(?i)(todo|tbd|coming soon|lorem ipsum|placeholder|privacy policy|terms of service)[.!]?",
        plain,
    ))


def _named(docs: list[_Doc], path_re: re.Pattern[str]) -> list[_Doc]:
    return [doc for doc in docs if path_re.search(doc.rel)]


def _detect_site_pages(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    pages = _pages(docs)
    if not pages:
        return []
    out: list[LaunchFinding] = []
    anchor = _site_anchor(pages)
    privacy_files = _named(docs, _PRIVACY_PATH)
    terms_files = _named(docs, _TERMS_PATH)
    dmca_files = _named(docs, _DMCA_PATH)
    privacy_link = any(_PRIVACY_LINK.search(doc.text) for doc in pages)
    terms_link = any(_TERMS_LINK.search(doc.text) for doc in pages)
    dmca_link = any(_DMCA_LINK.search(doc.text) for doc in docs)

    real_privacy = [doc for doc in privacy_files if not _policy_empty(doc.text)]
    empty_privacy = [doc for doc in privacy_files if _policy_empty(doc.text)]
    if empty_privacy and not real_privacy:
        out.append(_finding(rules, "empty-privacy-policy", _where(empty_privacy[0]), detail=empty_privacy[0].rel))
    elif not real_privacy and not privacy_link:
        out.append(_finding(rules, "missing-privacy-policy", _where(anchor), detail=anchor.rel))

    real_terms = [doc for doc in terms_files if not _policy_empty(doc.text)]
    empty_terms = [doc for doc in terms_files if _policy_empty(doc.text)]
    if empty_terms and not real_terms:
        out.append(_finding(rules, "empty-terms", _where(empty_terms[0]), detail=empty_terms[0].rel))
    elif not real_terms and not terms_link:
        out.append(_finding(rules, "missing-terms", _where(anchor), detail=anchor.rel))

    if not dmca_files and not dmca_link:
        out.append(_finding(rules, "missing-dmca-agent", _where(anchor), detail=anchor.rel))
        out.append(_finding(rules, "dmca-registration-steps", _where(anchor), detail=anchor.rel))
    return out


def _detect_trackers(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    hits = _vendor_hits(docs, list(rules.get("analytics") or []))
    if not hits:
        return []
    labels = [label for _vid, label, _doc, _snippet in hits]
    ad_ids = {str(vendor["id"]) for vendor in rules.get("analytics") or [] if vendor.get("ad")}
    ad = any(vid in ad_ids for vid, _label, _doc, _snippet in hits)
    first = hits[0]
    vendor_list = ", ".join(labels)
    consent = _phrases(rules, "recording_consent")
    has_consent = _repo_has(docs, consent)
    do_not_sell = _phrases(rules, "do_not_sell")
    gpc = _phrases(rules, "gpc")
    has_dns = _repo_has(docs, do_not_sell)
    has_gpc = _repo_has(docs, gpc)
    out: list[LaunchFinding] = []
    if not has_consent:
        out.append(_finding(
            rules, "analytics-before-consent", _where(first[2], first[3]),
            detail=first[2].rel, vendors=vendor_list,
        ))
    else:
        out.append(_finding(
            rules, "consent-order-unproven", _where(first[2], first[3]),
            detail=first[2].rel, vendors=vendor_list,
        ))
    if ad and not has_dns:
        out.append(_finding(
            rules, "ccpa-do-not-sell", _where(first[2], first[3]),
            detail=first[2].rel, vendors=vendor_list,
        ))
    elif not ad and not has_dns:
        out.append(_finding(
            rules, "ccpa-do-not-sell-checklist", _where(first[2], first[3]),
            detail=first[2].rel, vendors=vendor_list,
        ))
    elif has_dns and not has_gpc:
        out.append(_finding(
            rules, "ccpa-gpc-checklist", _where(first[2], first[3]),
            detail=first[2].rel, vendors=vendor_list,
        ))
    return out


def _detect_tcpa(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    optin = _phrases(rules, "sms_optin_phrases")
    sdk = _phrases(rules, "sms_sdk_snippets")
    marketing = _phrases(rules, "sms_marketing_phrases")
    consent = _phrases(rules, "sms_consent_phrases")
    transactional = _phrases(rules, "sms_transactional_phrases")
    for doc in _surface(docs):
        if doc.ext in _MD_EXTS | _STYLE_EXTS:
            continue
        has_optin = _has_phrase(doc.lower, optin) is not None
        has_sdk = _has_phrase(doc.lower, sdk) is not None
        if not has_optin and not has_sdk:
            continue
        has_marketing = _has_phrase(doc.lower, marketing) is not None
        has_consent = _has_phrase(doc.lower, consent) is not None
        has_transactional = _has_phrase(doc.lower, transactional) is not None
        if has_transactional and not has_marketing:
            continue
        if has_marketing and not has_consent:
            return [_finding(rules, "tcpa-sms-consent", _where(doc), detail=doc.rel)]
        if has_optin and not has_consent:
            return [_finding(rules, "tcpa-sms-review", _where(doc), detail=doc.rel)]
    return []


def _detect_ai(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    generative = _phrases(rules, "ai_generative_snippets")
    human = _phrases(rules, "ai_human_claims")
    gen_doc = next((doc for doc in docs if doc.ext not in _MD_EXTS and _has_phrase(doc.lower, generative)), None)
    human_doc = next((doc for doc in docs if _has_phrase(doc.lower, human)), None)
    if gen_doc is None or human_doc is None:
        return []
    return [_finding(
        rules, "ai-human-disclosure", _where(human_doc),
        detail=f"{human_doc.rel} (model code in {gen_doc.rel})",
    )]


def _detect_ugc(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    uploads = _phrases(rules, "upload_snippets")
    reports = _phrases(rules, "report_snippets")
    upload = next((
        doc for doc in docs
        if (doc.markup or doc.ext in _SCRIPT_EXTS | _CODE_EXTS) and _has_phrase(doc.lower, uploads)
    ), None)
    if upload is None:
        return []
    if _repo_has(docs, reports) or _named(docs, _DMCA_PATH):
        return []
    return [_finding(rules, "ugc-no-report-path", _where(upload), detail=upload.rel)]


def _detect_regulated(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    phi = _phrases(rules, "phi_snippets")
    finance = _phrases(rules, "finance_snippets")
    forms = _phrases(rules, "form_markers")
    out: list[LaunchFinding] = []
    for doc in docs:
        if doc.ext in _MD_EXTS | _STYLE_EXTS:
            continue
        if not _has_phrase(doc.lower, forms):
            continue
        if not any(item.rule == "hipaa-may-apply" for item in out) and _has_phrase(doc.lower, phi):
            out.append(_finding(rules, "hipaa-may-apply", _where(doc), detail=doc.rel))
        if not any(item.rule == "glba-may-apply" for item in out) and _has_phrase(doc.lower, finance):
            out.append(_finding(rules, "glba-may-apply", _where(doc), detail=doc.rel))
    return out


def _detect_a11y(docs: list[_Doc], rules: dict[str, Any]) -> list[LaunchFinding]:
    markup = [doc for doc in docs if doc.markup and doc.page]
    if not markup:
        return []
    images = 0
    alts = 0
    landmark = False
    first_img: _Doc | None = None
    for doc in markup:
        found = len(_IMG.findall(doc.text))
        if found and first_img is None:
            first_img = doc
        images += found
        alts += len(_ALT.findall(doc.text))
        if _LANDMARK.search(doc.text):
            landmark = True
    if images >= 1 and alts == 0 and not landmark and first_img is not None:
        return [_finding(rules, "a11y-primary-page", _where(first_img, "<img"), detail=first_img.rel)]
    return []


def _detect_oss(
    docs: list[_Doc], rules: dict[str, Any], files: list[Path], root: Path,
) -> list[LaunchFinding]:
    oss = rules.get("oss") or {}
    vendor_dirs = {str(name).lower() for name in oss.get("vendor_dirs") or ()}
    notice_names = {str(name).lower() for name in oss.get("notice_names") or ()}
    markers = tuple(str(item).lower() for item in oss.get("license_markers") or ())
    for path in files:
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if rel.name.lower() in notice_names:
            return []
    for doc in docs:
        parts = {part.lower() for part in Path(doc.rel).parts[:-1]}
        if not parts & vendor_dirs:
            continue
        if _has_phrase(doc.raw_lower, markers):
            return [_finding(rules, "missing-oss-notice", _where(doc), detail=doc.rel)]
    return []


def _native_sarif(findings: list[LaunchFinding], tool_version: str) -> dict[str, Any]:
    return simple_sarif(
        findings,
        tool="tridelphi-launch",
        audit_label="Launch legal audit",
        tool_version=tool_version,
        help_uri=_HELP_URI,
    )


def analyze_launch(
    root: str | Path,
    *,
    tool_version: str = "0",
    limits: ExposureLimits | None = None,
) -> LaunchResult:
    """Read ``root`` and report launch-time legal patterns. Offline."""
    supplied = Path(root)
    if supplied.is_symlink():
        raise ValueError("launch root must not be a symlink")
    root_path = supplied.resolve()
    if not root_path.is_dir():
        raise ValueError(f"{supplied} is not a directory")
    limits = limits or ExposureLimits()
    if min(limits.max_files, limits.max_total_bytes, limits.max_file_bytes) <= 0:
        raise ValueError("launch limits must be positive")
    if limits.max_seconds <= 0:
        raise ValueError("launch time limit must be positive")
    coverage = ExposureCoverage(deadline=time.monotonic() + limits.max_seconds)
    files = _walk(root_path, limits, coverage)
    rules = _rules()
    docs = _load_docs(root_path, files, coverage, limits.max_file_bytes)
    findings: list[LaunchFinding] = []
    findings += _detect_coppa(docs, rules)
    findings += _detect_fonts(docs, rules)
    findings += _detect_replay(docs, rules)
    findings += _detect_canspam(docs, rules)
    findings += _detect_renewal(docs, rules)
    findings += _detect_site_pages(docs, rules)
    findings += _detect_trackers(docs, rules)
    findings += _detect_tcpa(docs, rules)
    findings += _detect_ai(docs, rules)
    findings += _detect_ugc(docs, rules)
    findings += _detect_regulated(docs, rules)
    findings += _detect_oss(docs, rules, files, root_path)
    findings += _detect_a11y(docs, rules)
    findings.sort(key=lambda item: (
        CATEGORY_ORDER.get(item.category, 99),
        SEVERITY_ORDER.get(item.severity, 9),
        item.where,
        item.rule,
    ))
    return LaunchResult(findings=findings, sarif=_native_sarif(findings, tool_version), coverage=coverage)
