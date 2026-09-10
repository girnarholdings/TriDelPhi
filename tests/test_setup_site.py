"""Static accessibility and security contracts for the Setup Studio."""

from __future__ import annotations

import re
from html.parser import HTMLParser


class _Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.controls: list[str] = []
        self.statuses: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if values.get("aria-controls"):
            self.controls.append(values["aria-controls"])
        if values.get("role") == "status":
            self.statuses.append(values)


def _contrast(left: str, right: str) -> float:
    def luminance(value: str) -> float:
        channels = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        channels = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    high, low = sorted((luminance(left), luminance(right)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_setup_site_accessibility_and_generator_guards(repo_root):
    text = (repo_root / "site/setup.html").read_text(encoding="utf-8")
    document = _Document()
    document.feed(text)

    assert document.controls and all(target in document.ids for target in document.controls)
    assert len(document.ids) == len(set(document.ids))
    assert document.statuses and all(status.get("aria-live") == "polite" for status in document.statuses[:1])
    assert ":focus-visible" in text
    assert "prefers-reduced-motion: reduce" in text
    assert "yamlBlock(elBuild.value.trim()" in text
    assert '"        run: " + (elBuild.value' not in text
    assert "application/json-malformed" not in text
    assert "Copy failed" in text
    assert "choices never leave" not in text
    assert 'if (Number(level()) >= 6)' in text
    assert '"  id-token: write", "  attestations: write"' in text
    assert "tee -a" not in text
    assert 'REPORT_MD=\\"$RUNNER_TEMP/tridelphi-expose.md\\"' in text
    assert '--checklist-md-file \\"$REPORT_MD\\"' in text


def test_setup_color_tokens_meet_normal_text_contrast(repo_root):
    text = (repo_root / "site/setup.html").read_text(encoding="utf-8")
    root = re.search(r":root\{(?P<body>.*?)\n\}", text, re.DOTALL)
    assert root
    tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", root.group("body")))
    for foreground in ("ink", "mute", "faint", "grn-ink"):
        assert _contrast(tokens[foreground], tokens["bg"]) >= 4.5, foreground
