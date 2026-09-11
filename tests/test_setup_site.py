"""Static accessibility and security contracts for the Setup Studio."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest


class _Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.controls: list[str] = []
        self.statuses: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
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
    assert "#0c110e" not in text
    assert "./#ladder" not in text
    assert text.count("# Docs: https://tridelphi.com/") == 2
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


def test_setup_browser_workflows_and_interactions(repo_root):
    """Opt-in real-browser matrix: SETUP_NODE plus Playwright on NODE_PATH.

    Uses a fresh headless browser, local files only, and never executes workflows.
    SETUP_BROWSER_CHANNEL=chrome can use an already installed Chrome.
    """
    node = os.environ.get("SETUP_NODE") or shutil.which("node")
    if not node:
        pytest.skip("Set SETUP_NODE to run the Playwright setup regression matrix")
    probe = subprocess.run([node, "-e", "require('playwright')"], capture_output=True)
    if probe.returncode:
        pytest.skip("Playwright must be available on NODE_PATH")
    script = r"""
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const {pathToFileURL} = require('node:url');
(async () => {
  const browser = await chromium.launch({headless:true,
    ...(process.env.SETUP_BROWSER_CHANNEL ? {channel:process.env.SETUP_BROWSER_CHANNEL} : {})});
  try {
    const page = await browser.newPage({reducedMotion:'reduce'});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route(/^https?:/, route => route.abort());
    const url = pathToFileURL(process.argv[1] + '/site/setup.html').href;
    await page.goto(url);
    await page.locator('#yaml').filter({hasText:'name: TriDelPhi app audit'}).waitFor();
    assert.equal(await page.locator('#b-build').evaluate(el => el.inert), true);
    await page.locator('input[value="app"]').focus();
    await page.keyboard.press('ArrowRight');
    assert.equal(await page.locator('input[value="ci"]').isChecked(), true);
    assert.equal(await page.locator('#r-path .rung-h').getAttribute('aria-expanded'), 'true');
    await page.keyboard.press('ArrowLeft');
    assert.equal(await page.locator('input[value="app"]').isChecked(), true);
    const apps = [];
    for (const command of ['', '   ', 'npm ci && npm run build', 'echo "a: b # c"',
      'echo café 日本語', 'echo ' + 'x'.repeat(10000)]) {
      await page.locator('#buildcmd').fill(command);
      apps.push({command, yaml:await page.locator('#yaml').textContent()});
    }
    await page.locator('#buildcmd').fill('npm run build');
    await page.evaluate(() => {
      window.previewMutations = 0;
      new MutationObserver(records => window.previewMutations += records.length)
        .observe(document.getElementById('yaml'), {childList:true, subtree:true});
    });
    for (const repo of ['octocat/hello-world', ' https://github.com/octocat/.github/ ',
      'owner/_repo-', 'owner/' + 'r'.repeat(100)]) {
      await page.locator('#repo').fill(repo);
      assert.equal(await page.locator('#createBtn').getAttribute('aria-disabled'), 'false');
      const link = new URL(await page.locator('#createBtn').getAttribute('href'));
      assert.equal(link.searchParams.get('value'), await page.locator('#yaml').textContent());
      assert.equal(link.searchParams.get('filename'), '.github/workflows/tridelphi-app.yml');
    }
    for (const repo of ['', 'owner', 'owner/repo/extra', 'https://evil.test/owner/repo',
      'owner/..', 'owner/.', 'owner/repo?x=1', 'owner/repo#fragment', 'a--b/repo',
      'owner/' + 'r'.repeat(101), '日本語/repo', 'owner/<script>']) {
      await page.locator('#repo').fill(repo);
      assert.equal(await page.locator('#createBtn').getAttribute('href'), null);
      assert.equal(await page.locator('#repo').getAttribute('aria-invalid'), repo ? 'true' : 'false');
    }
    assert.equal(await page.evaluate(() => window.previewMutations), 0);
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard',
      {value:{writeText:() => Promise.reject(new Error('denied'))}, configurable:true}));
    await page.locator('#copyBtn').click();
    await page.locator('#copied').filter({hasText:'Copy failed'}).waitFor();
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard',
      {value:{writeText:text => { window.copiedWorkflow = text; return Promise.resolve(); }}}));
    await page.locator('#copyBtn').click();
    assert.equal(await page.evaluate(() => window.copiedWorkflow), await page.locator('#yaml').textContent());
    await page.goto(url + '?path=ci-not-a-mode');
    assert.equal(await page.locator('input[value="app"]').isChecked(), true);
    await page.goto(url + '?path=ci');
    assert.equal(await page.locator('input[value="ci"]').isChecked(), true);
    const workflows = await page.evaluate(() => {
      const output = [];
      for (let level=0; level<=7; level++) for (const fail of ['critical','warning','none'])
      for (const comment of [false,true]) for (const expose of [false,true]) {
        document.getElementById('lvl').value = level;
        document.getElementById('failon').value = fail;
        document.getElementById('comment').checked = comment;
        document.getElementById('expose').checked = expose;
        document.getElementById('lvl').dispatchEvent(new Event('input', {bubbles:true}));
        output.push({level,fail,comment,expose,yaml:document.getElementById('yaml').textContent,
          snippet:document.getElementById('oneline').textContent});
      }
      return output;
    });
    for (const width of [320,390,1280]) {
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
    for (const [name,width,scheme] of [['desktop',1280,'dark'],['mobile',390,'light']]) {
      await page.setViewportSize({width,height:900});
      await page.emulateMedia({colorScheme:scheme});
      await page.goto(url);
      await page.evaluate(() => document.fonts.ready);
      if (process.env.SETUP_SCREENSHOT_DIR) await page.screenshot({
        path:process.env.SETUP_SCREENSHOT_DIR + '/setup-' + name + '.png', fullPage:true});
      await page.setViewportSize({width:320,height:900});
      await page.evaluate(() => document.documentElement.style.fontSize = '200%');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({apps,workflows}));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
"""
    result = subprocess.run(
        [node, "-e", script, str(repo_root)], capture_output=True, text=True, timeout=90
    )
    assert result.returncode == 0, result.stderr
    from ruamel.yaml import YAML

    parser = YAML(typ="safe")
    data = json.loads(result.stdout)
    for app in data["apps"]:
        workflow = parser.load(app["yaml"])
        steps = workflow["jobs"]["audit"]["steps"]
        assert steps[1]["run"].rstrip() == (app["command"].strip() or "npm ci && npm run build")
        assert workflow["permissions"] == {"contents": "read"}
        assert "--fail-on none" in steps[-1]["run"]
    assert len(data["workflows"]) == 96
    for case in data["workflows"]:
        workflow = parser.load(case["yaml"])
        assert set(workflow["on"]) == {"push", "pull_request", "workflow_dispatch"}
        steps = workflow["jobs"]["harden"]["steps"]
        assert steps[0]["with"]["persist-credentials"] is False
        settings = steps[1]["with"]
        assert settings["level"] == str(case["level"])
        assert settings["fail-on"] == case["fail"]
        assert settings["comment"] == str(case["comment"]).lower()
        assert (settings.get("expose") == "true") == case["expose"]
        assert parser.load(case["snippet"])[0] == steps[1]
        permissions = {"contents": "read", "security-events": "write"}
        if case["comment"]:
            permissions["pull-requests"] = "write"
        if case["level"] >= 6:
            permissions.update({"id-token": "write", "attestations": "write"})
        assert workflow["permissions"] == permissions
