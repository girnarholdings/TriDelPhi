"""`tridelphi launch` — lawsuit traps, offline, not legal advice.

Seed traps must fire on the vibe-app fixture. The clean-app fixture and the
narrow controls must stay quiet. A clean result is not a certificate, and the
report has to say so.
"""

from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest

from tridelphi.expose import ExposureLimits
from tridelphi.launch import NOT_LEGAL_ADVICE, analyze_launch, load_launch_rules
from tridelphi.launch_cmd import run_launch

FIXTURES = Path(__file__).parent / "fixtures" / "launch"
VIBE = FIXTURES / "vibe-app"
CLEAN = FIXTURES / "clean-app"

_SEED = {
    "coppa-age-gate",
    "third-party-font",
    "session-replay",
    "can-spam-footer",
    "auto-renewal-terms",
    "missing-dmca-agent",
}


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    # Each call gets its own directory. Tests that build a control after a
    # trap must not inherit the trap's files.
    root = tmp_path / f"case{sum(1 for _ in tmp_path.iterdir())}"
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _rules(root: Path) -> set[str]:
    return {finding.rule for finding in analyze_launch(root, tool_version="0").findings}


def _one(root: Path, rule: str):
    found = [finding for finding in analyze_launch(root).findings if finding.rule == rule]
    assert found, rule
    return found[0]


def test_rule_table_loads_and_names_only_the_briefed_amounts():
    rules = load_launch_rules()
    assert rules["version"] == 2
    ids = [row["id"] for row in rules["rules"]]
    assert len(ids) == len(set(ids))
    assert "ai-chatbot-disclosure" in ids
    assert "a11y-missing-alt" in ids
    categories = {row["id"] for row in rules["categories"]}
    assert {row["category"] for row in rules["rules"]} <= categories
    for row in rules["rules"]:
        assert "http" in str(row["citation"]).lower(), row["id"]
        assert str(row.get("snippet") or "").strip(), row["id"]
    blob = "\n".join(str(row["message"]) + "\n" + str(row["fix"]) for row in rules["rules"])
    assert "53,000" in blob and "5,000" in blob and "$6" in blob
    allowed = blob.replace("$53,000", "").replace("$5,000", "").replace("$6", "")
    assert "$" not in allowed
    assert "not legal advice" in NOT_LEGAL_ADVICE.lower()


def test_vibe_fixture_reports_the_seed_six():
    result = analyze_launch(VIBE, tool_version="0")
    found = {finding.rule for finding in result.findings}
    assert found >= _SEED
    assert result.coverage.complete
    by_rule = {finding.rule: finding for finding in result.findings}
    assert by_rule["coppa-age-gate"].severity == "warning"
    assert "COPPA" in by_rule["coppa-age-gate"].message
    assert "53,000" in by_rule["coppa-age-gate"].message
    assert "fonts.googleapis.com" in by_rule["third-party-font"].message
    assert "Hotjar" in by_rule["session-replay"].message
    assert "5,000" in by_rule["session-replay"].message
    assert "unsubscribe" in by_rule["can-spam-footer"].message
    assert "postal" in by_rule["can-spam-footer"].message
    assert "auto-renewal" in by_rule["auto-renewal-terms"].message.lower() or "ARL" in by_rule["auto-renewal-terms"].message
    assert by_rule["dmca-registration-steps"].kind == "checklist"
    assert "$6" in by_rule["dmca-registration-steps"].fix
    assert "did not submit" in by_rule["dmca-registration-steps"].fix.lower()
    assert "missing-privacy-policy" in found
    assert "missing-terms" in found
    assert "analytics-before-consent" in found
    assert "ugc-no-report-path" in found
    assert "a11y-primary-page" in found
    assert "hipaa-may-apply" not in found
    assert "tcpa-sms-consent" not in found


def test_clean_fixture_stays_quiet():
    result = analyze_launch(CLEAN, tool_version="0")
    assert result.findings == []
    assert result.coverage.complete


def test_report_says_it_is_not_legal_advice():
    buf = io.StringIO()
    code = run_launch(str(CLEAN), fmt="text", out=buf, fail_on="warning")
    assert code == 0
    text = " ".join(buf.getvalue().split())
    assert "not legal advice" in text.lower()
    assert "not a compliance certificate" in text.lower()
    md = io.StringIO()
    run_launch(str(VIBE), fmt="markdown", out=md, fail_on="none")
    assert "not legal advice" in md.getvalue().lower()


def test_seed_warnings_do_not_fail_the_default_gate():
    assert run_launch(str(VIBE), fmt="text", out=io.StringIO()) == 0
    assert run_launch(str(VIBE), fmt="text", out=io.StringIO(), fail_on="warning") == 1
    assert run_launch(str(VIBE), fmt="text", out=io.StringIO(), fail_on="none") == 0


def test_sarif_carries_launch_rules():
    buf = io.StringIO()
    assert run_launch(str(VIBE), fmt="sarif", out=buf, fail_on="none") == 0
    document = json.loads(buf.getvalue())
    assert document["version"] == "2.1.0"
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert any(rule["id"] == "tridelphi-launch/coppa-age-gate" for rule in rules)
    assert all("not legal advice" in result["message"]["text"].lower()
               for result in document["runs"][0]["results"])


def test_bad_path_and_symlink_exit_2(tmp_path: Path):
    assert run_launch(str(tmp_path / "missing"), out=io.StringIO(), err=io.StringIO()) == 2
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    assert run_launch(str(link), out=io.StringIO(), err=io.StringIO()) == 2


def test_partial_coverage_is_not_a_pass(tmp_path: Path):
    root = _repo(tmp_path, {"a.html": "<p>hi</p>", "b.html": "<p>there</p>"})
    buf = io.StringIO()
    code = run_launch(
        str(root), fmt="text", out=buf, err=io.StringIO(),
        limits=ExposureLimits(max_files=1),
    )
    assert code == 2
    assert "PARTIAL" in buf.getvalue()
    assert "certificate" in buf.getvalue().lower()


def test_launch_does_not_touch_the_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("launch must not use the network or a subprocess")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    root = _repo(tmp_path, {"lib.py": "def add(a, b):\n    return a + b\n"})
    assert analyze_launch(root).findings == []


def test_login_and_readme_and_self_hosted_font_stay_quiet(tmp_path: Path):
    root = _repo(tmp_path, {
        "login.html": """
            <form><h1>Sign in</h1>
            <input type="password" name="password">
            <a href="/signup">Sign up</a></form>
            <a href="/privacy">Privacy</a>
            <a href="/terms">Terms</a>
            <a href="/dmca">DMCA</a>
        """,
        "privacy.html": "<p>We collect an email address so you can sign in, and we say so on this page for visitors.</p>",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent: Ada Lovelace, 1 Market Street, Springfield, IL 62701.</p>",
        "README.md": "Do not load https://fonts.googleapis.com/css in production.",
        "app/fonts.ts": 'import { Inter } from "next/font/google";\n',
        "styles.css": '@font-face { font-family: Inter; src: url("/fonts/inter.woff2"); }\n',
    })
    assert _rules(root) == set()


def test_typekit_and_replay_without_consent_fire(tmp_path: Path):
    root = _repo(tmp_path, {
        "index.html": """
            <link href="https://use.typekit.net/abc.css" rel="stylesheet">
            <script src="https://cdn.logrocket.io/LogRocket.min.js"></script>
            <script>LogRocket.init("x");</script>
            <a href="/privacy">Privacy policy</a>
            <a href="/terms">Terms</a>
            <a href="/dmca">DMCA</a>
        """,
        "privacy.html": "<p>We collect an email address so you can sign in, and we say so on this page for visitors.</p>",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    found = _rules(root)
    assert "third-party-font" in found
    assert "session-replay" in found
    assert "use.typekit.net" in _one(root, "third-party-font").message


def test_replay_with_consent_and_masking_stays_quiet(tmp_path: Path):
    root = _repo(tmp_path, {
        "index.html": """
            <div id="cookieconsent">Accept cookies</div>
            <script src="https://static.hotjar.com/c/hotjar-1.js" data-hj-masked></script>
            <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/dmca">DMCA</a>
        """,
        "privacy.html": "<p>We collect an email address so you can sign in, and we say so on this page for visitors.</p>",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    assert "session-replay" not in _rules(root)
    assert "session-replay-unmasked" not in _rules(root)


def test_posthog_bare_init_is_a_checklist_and_explicit_off_is_quiet(tmp_path: Path):
    bare = _repo(tmp_path, {"app.js": "posthog.init('phc_x', { api_host: 'https://app.posthog.com' });\n"})
    assert "posthog-replay-default" in _rules(bare)
    assert "session-replay" not in _rules(bare)
    off = _repo(tmp_path, {
        "app.js": "posthog.init('phc_x', { disable_session_recording: true });\n",
    })
    assert "posthog-replay-default" not in _rules(off)
    assert "session-replay" not in _rules(off)


def test_transactional_email_stays_quiet_and_marketing_needs_both_lines(tmp_path: Path):
    reset = _repo(tmp_path, {
        "emails/reset.html": "<p>Reset your password. This link expires in 30 minutes.</p>",
    })
    assert "can-spam-footer" not in _rules(reset)
    half = _repo(tmp_path, {
        "emails/newsletter.html": "<p>Newsletter. 20% off. <a href=\"/unsubscribe\">Unsubscribe</a></p>",
    })
    finding = _one(half, "can-spam-footer")
    assert "postal" in finding.message
    assert "unsubscribe" not in finding.message


def test_renewal_copy_next_to_the_button_stays_quiet(tmp_path: Path):
    root = _repo(tmp_path, {
        "checkout.html": """
            <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/dmca">DMCA</a>
            <button>Subscribe</button>
            <p>$12 per month. Renews until you cancel. Cancel anytime.</p>
        """,
        "privacy.html": "<p>We collect an email address so you can sign in, and we say so on this page for visitors.</p>",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    assert "auto-renewal-terms" not in _rules(root)
    assert "auto-renewal-review" not in _rules(root)


def test_subscribe_without_a_price_is_a_checklist(tmp_path: Path):
    root = _repo(tmp_path, {"pricing.html": "<button>Subscribe</button><p>Pro plan membership.</p>"})
    finding = _one(root, "auto-renewal-review")
    assert finding.severity == "note"
    assert finding.kind == "checklist"


def test_empty_privacy_page_is_not_a_policy(tmp_path: Path):
    root = _repo(tmp_path, {
        "index.html": "<main><p>Hello</p></main>",
        "privacy.html": "TODO",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    assert "empty-privacy-policy" in _rules(root)
    assert "missing-privacy-policy" not in _rules(root)


def test_ad_pixel_without_do_not_sell_is_a_warning(tmp_path: Path):
    root = _repo(tmp_path, {
        "index.html": """
            <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
            <div id="cookieconsent">Accept cookies</div>
            <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/dmca">DMCA</a>
        """,
        "privacy.html": "<p>We collect an email address so you can sign in, and we say so on this page for visitors.</p>",
        "terms.html": "<p>These terms describe the account and how to close it. Questions go to legal@example.com today.</p>",
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    finding = _one(root, "ccpa-do-not-sell")
    assert finding.severity == "warning"
    assert "CCPA" in finding.message
    assert "$" not in finding.message


def test_sms_marketing_needs_express_consent_and_otp_stays_quiet(tmp_path: Path):
    promo = _repo(tmp_path, {
        "sms.html": "<form><p>Text me the promo deals</p><input name=\"phone\"></form>",
    })
    assert _one(promo, "tcpa-sms-consent").severity == "warning"
    assert "$" not in _one(promo, "tcpa-sms-consent").message
    ok = _repo(tmp_path, {
        "sms.html": (
            "<form><p>Text me promo offers. I give express consent to receive "
            "marketing texts. Message frequency varies. Msg & data rates may apply.</p></form>"
        ),
    })
    assert "tcpa-sms-consent" not in _rules(ok)
    otp = _repo(tmp_path, {
        "notify.py": 'client.messages.create(body="Your verification code is 4242")\n',
    })
    assert "tcpa-sms-consent" not in _rules(otp)
    assert "tcpa-sms-review" not in _rules(otp)


def test_health_and_bank_forms_are_high_severity_checklists(tmp_path: Path):
    health = _repo(tmp_path, {
        "intake.html": '<form><input name="diagnosis"><input name="prescription"></form>',
    })
    finding = _one(health, "hipaa-may-apply")
    assert finding.severity == "warning"
    assert finding.kind == "checklist"
    assert "not a HIPAA audit" in finding.message
    blog = _repo(tmp_path, {"notes.md": "A diagnosis is not something this essay collects."})
    assert "hipaa-may-apply" not in _rules(blog)
    bank = _repo(tmp_path, {
        "bank.html": '<form><input name="routing_number"><input name="bank_account"></form>',
    })
    glba = _one(bank, "glba-may-apply")
    assert glba.kind == "checklist"
    assert "not a GLBA audit" in glba.message


def test_ai_disclosure_needs_both_signals(tmp_path: Path):
    both = _repo(tmp_path, {
        "gen.py": "import openai\n",
        "about.html": "<p>Every essay is written by our team of experts.</p>",
    })
    assert _one(both, "ai-human-disclosure").kind == "checklist"
    only_model = _repo(tmp_path, {"gen.py": "import openai\n"})
    assert "ai-human-disclosure" not in _rules(only_model)


def test_upload_with_a_report_link_stays_quiet(tmp_path: Path):
    root = _repo(tmp_path, {
        "upload.html": '<form><input type="file"></form><a href="/dmca">Report this</a>',
        "dmca.html": "<p>Designated agent page with a real mailing address and email for notices.</p>",
    })
    assert "ugc-no-report-path" not in _rules(root)


def test_vendored_mit_without_notice_is_a_checklist(tmp_path: Path):
    missing = _repo(tmp_path, {"vendor/chart.js": "/* MIT License */\nexport const chart = 1;\n"})
    assert _one(missing, "missing-oss-notice").severity == "note"
    present = _repo(tmp_path, {
        "vendor/chart.js": "/* MIT License */\nexport const chart = 1;\n",
        "NOTICE": "chart.js is MIT.\n",
    })
    assert "missing-oss-notice" not in _rules(present)


def test_accessibility_note_is_high_signal(tmp_path: Path):
    bare = _repo(tmp_path, {"index.html": '<img src="/a.png"><img src="/b.png">'})
    assert "a11y-primary-page" in _rules(bare)
    assert "a11y-missing-alt" in _rules(bare)
    alt = _repo(tmp_path, {"index.html": '<img src="/a.png" alt="">'})
    assert "a11y-primary-page" not in _rules(alt)
    assert "a11y-missing-alt" not in _rules(alt)
    landmark = _repo(tmp_path, {"index.html": '<main><img src="/a.png"></main>'})
    assert "a11y-primary-page" not in _rules(landmark)
    assert "a11y-missing-alt" in _rules(landmark)


def test_library_without_a_website_is_not_told_it_lacks_a_privacy_policy(tmp_path: Path):
    root = _repo(tmp_path, {"tridelphi_example/lib.py": "def add(a, b):\n    return a + b\n"})
    assert _rules(root) == set()


def test_report_prints_a_fix_snippet_and_a_source():
    buf = io.StringIO()
    assert run_launch(str(VIBE), fmt="text", out=buf, fail_on="none") == 0
    text = buf.getvalue()
    assert "Source:" in text
    assert "https://" in text
    assert "Date of birth" in text


def test_sarif_help_uri_is_the_primary_source():
    buf = io.StringIO()
    assert run_launch(str(VIBE), fmt="sarif", out=buf, fail_on="none") == 0
    document = json.loads(buf.getvalue())
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    coppa = next(rule for rule in rules if rule["id"] == "tridelphi-launch/coppa-age-gate")
    assert "federalregister.gov" in coppa["helpUri"]
    result = next(
        item for item in document["runs"][0]["results"]
        if item["ruleId"] == "tridelphi-launch/coppa-age-gate"
    )
    assert "Source:" in result["message"]["text"]
    assert "Example:" in result["message"]["text"]
    assert "not legal advice" in result["message"]["text"].lower()


def test_next_and_vite_trap_fixtures_name_the_new_traps():
    next_found = _rules(FIXTURES / "next-trap")
    assert next_found >= {
        "coppa-age-gate",
        "third-party-font",
        "session-replay",
        "can-spam-footer",
        "auto-renewal-terms",
        "missing-dmca-agent",
        "missing-privacy-policy",
        "missing-terms",
        "analytics-before-consent",
        "ai-chatbot-disclosure",
        "a11y-missing-alt",
    }
    messages = " ".join(
        finding.message for finding in analyze_launch(FIXTURES / "next-trap").findings
    )
    assert "Sentry" in messages
    assert "Intercom" in messages
    assert "FullStory" not in messages
    assert "Lucky Orange" not in messages
    assert "hipaa-may-apply" not in next_found
    vite = _rules(FIXTURES / "vite-trap")
    assert vite >= {
        "coppa-age-gate",
        "third-party-font",
        "session-replay",
        "auto-renewal-terms",
        "missing-dmca-agent",
        "missing-privacy-policy",
        "missing-terms",
        "analytics-before-consent",
        "a11y-missing-alt",
    }
    vite_messages = " ".join(
        finding.message for finding in analyze_launch(FIXTURES / "vite-trap").findings
    )
    assert "Hotjar" in vite_messages


def test_next_and_vite_clean_fixtures_stay_quiet():
    assert analyze_launch(FIXTURES / "next-clean").findings == []
    assert analyze_launch(FIXTURES / "vite-clean").findings == []


def test_python_detector_mentioning_posthog_is_not_a_recorder(tmp_path: Path):
    root = _repo(tmp_path, {
        "detectors.py": 'started = "startsessionrecording" in text\n',
    })
    assert "session-replay" not in _rules(root)
    assert "posthog-replay-default" not in _rules(root)


def test_comment_minified_and_docs_do_not_count_as_the_app(tmp_path: Path):
    commented = _repo(tmp_path, {
        "app.tsx": "// https://fonts.googleapis.com/css2?family=Inter\nexport const x = 1;\n",
        "public/lo.min.js": 'var s="https://tools.luckyorange.com/core/lo.js";\n',
    })
    assert "third-party-font" not in _rules(commented)
    assert "session-replay" not in _rules(commented)
    docs = _repo(tmp_path, {
        "index.html": "<main><p>Hello visitor</p></main>",
        "docs/policy.md": "The footer links to /dmca and names a designated agent.",
        "rules.yml": 'example: name="diagnosis"\n',
    })
    found = _rules(docs)
    assert "missing-dmca-agent" in found
    assert "hipaa-may-apply" not in found


@pytest.mark.parametrize("files", [
    {"index.html": '<head><link href="//fonts.googleapis.com/css?family=Roboto" rel="stylesheet"></head>'},
    {"styles.scss": "@import url(//fonts.googleapis.com/css?family=Roboto);\n"},
    {"server.js": (
        'app.get("/*", (req, res) => res.send(page));\n'
        'const page = `<link href="https://fonts.googleapis.com/css2?family=Inter">`;\n'
        "/* serve the shell */\n"
    )},
], ids=["protocol-relative-href", "scss-url", "glob-route-before-comment"])
def test_slashes_inside_strings_are_not_comments(tmp_path: Path, files):
    """A comment pattern blanked these, and the font the page loads went unseen."""
    assert "third-party-font" in _rules(_repo(tmp_path, files))


def test_only_the_setuptools_build_lib_is_not_the_app(tmp_path: Path):
    page = '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">'
    assert "third-party-font" in _rules(_repo(tmp_path, {"web/build/lib/index.html": page}))
    assert "third-party-font" not in _rules(_repo(tmp_path, {"build/lib/pkg/index.html": page}))
