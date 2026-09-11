"""Validate the buildless public site without fetching any remote resources."""

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1] / "site"
ORIGIN = "https://tridelphi.com"


def validate_site(root=ROOT):
    problems = []

    def asset(value, source):
        url = urlsplit(value)
        if url.scheme == "data":
            return
        if url.scheme or url.netloc:
            problems.append(f"{source.name}: external asset {value}")
            return
        target = (root / unquote(url.path).lstrip("/") if url.path.startswith("/")
                  else source.parent / unquote(url.path)).resolve()
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            problems.append(f"{source.name}: missing or unsafe asset {value}")

    class Document(HTMLParser):
        def __init__(self, source):
            super().__init__()
            self.source = source
            self.ids = set()
            self.local_anchors = []
            self.title = False
            self.canonical = False

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if "id" in a:
                if a["id"] in self.ids:
                    problems.append(f"{self.source.name}: duplicate id {a['id']}")
                self.ids.add(a["id"])
            if tag == "title":
                self.title = True
            if a.get("src"):
                asset(a["src"], self.source)
            if a.get("srcset"):
                for candidate in a["srcset"].split(","):
                    if candidate.strip():
                        asset(candidate.strip().split()[0], self.source)
            if tag == "link" and a.get("href"):
                if "canonical" in a.get("rel", "").split():
                    expected = ORIGIN + ("/" if self.source.name == "index.html" else "/" + self.source.name)
                    self.canonical = a["href"] == expected
                else:
                    asset(a["href"], self.source)
            if tag == "a" and a.get("href", "").startswith("#"):
                self.local_anchors.append(a["href"][1:])
            elif tag == "a" and a.get("href"):
                target = urlsplit(a["href"])
                if not target.scheme and not target.netloc:
                    path = target.path
                    if path.endswith("/"):
                        path += "index.html"
                    asset(path, self.source)
            if tag == "meta" and (a.get("property") == "og:image" or a.get("name") == "twitter:image"):
                value = a.get("content", "")
                if not value.startswith(ORIGIN + "/"):
                    problems.append(f"{self.source.name}: incorrect social image origin")
                else:
                    asset(value[len(ORIGIN):], self.source)

    for source in root.glob("*.html"):
        content = source.read_text(encoding="utf-8")
        document = Document(source)
        document.feed(content)
        if re.search(r"@import\b", content):
            problems.append(f"{source.name}: CSS imports are not supported")
        if not document.title or not document.canonical:
            problems.append(f"{source.name}: missing title or incorrect canonical")
        for anchor in document.local_anchors:
            if anchor and anchor not in document.ids:
                problems.append(f"{source.name}: missing anchor #{anchor}")
        for value in re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", content):
            asset(value, source)
    for source in root.rglob("*.css"):
        content = source.read_text(encoding="utf-8")
        if re.search(r"@import\b", content):
            problems.append(f"{source.name}: CSS imports are not supported")
        for value in re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", content):
            asset(value, source)
    return problems


if __name__ == "__main__":
    problems = validate_site()
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print("Site OK: local assets, canonical URLs, social images, IDs and anchors")
