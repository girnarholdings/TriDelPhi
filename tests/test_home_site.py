"""Contracts for the public two-studio website."""

import runpy


def test_public_site_assets_and_metadata(repo_root):
    check = runpy.run_path(str(repo_root / "scripts/check-site.py"))
    assert check["validate_site"]() == []


def test_homepage_explains_both_real_routes(repo_root):
    text = (repo_root / "site/index.html").read_text()
    assert "Manual Setup Studio" in text and "Cloud Scan Studio" in text
    assert 'href="setup.html"' in text
    assert 'href="https://scan.tridelphi.com/"' in text
    assert "GitHub charges may apply" in text
    assert "not antivirus" in text
    assert "does not mean the scan has already run" in text
    assert "Nothing is uploaded" not in text
    assert "cdn." not in text


def test_canonical_is_not_treated_as_remote_asset(tmp_path, repo_root):
    check = runpy.run_path(str(repo_root / "scripts/check-site.py"))
    page = tmp_path / "index.html"
    page.write_text('<title>Example</title><link rel="canonical" href="https://tridelphi.com/">')
    assert check["validate_site"](tmp_path) == []
    page.write_text(page.read_text() + '<script src="https://example.com/tracker.js"></script>')
    assert any("external asset" in item for item in check["validate_site"](tmp_path))


def test_local_navigation_must_resolve_inside_site(tmp_path, repo_root):
    check = runpy.run_path(str(repo_root / "scripts/check-site.py"))
    page = tmp_path / "index.html"
    head = '<title>Example</title><link rel="canonical" href="https://tridelphi.com/">'
    page.write_text(head + '<a href="./">Home</a><a href="setup.html">Setup</a>')
    assert any("setup.html" in item for item in check["validate_site"](tmp_path))
    page.write_text(head + '<a href="./">Home</a><a href="https://scan.tridelphi.com/">Cloud</a>')
    assert check["validate_site"](tmp_path) == []
    page.write_text(head + '<img src="%2e%2e/private.png">')
    assert any("unsafe asset" in item for item in check["validate_site"](tmp_path))
