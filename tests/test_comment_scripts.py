"""The sticky PR comment, exercised under Node against a mock GitHub client.

Every workflow that posts TriDelPhi's report finds its earlier comment by a
marker. Matching on the marker alone let anyone plant it in a comment of their
own: the edit then failed with a 403, the step threw, and the gate step after
it never ran. Reading only the first page duplicated the report on long
threads. These run the real script bodies, not a copy.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from tridelphi.init_cmd import APP_WORKFLOW, WORKFLOW

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

HARNESS = r"""
const [body, marker, scenario] = JSON.parse(process.argv[1]);
const calls = [];
const warnings = [];
const bot = { login: 'github-actions[bot]', type: 'Bot' };
const stranger = { login: 'mallory', type: 'User' };
const pages = {
  planted: [[{ id: 1, user: stranger, body: marker + ' planted' }]],
  second_page: [
    Array.from({ length: 100 }, (_, i) => ({ id: 100 + i, user: stranger, body: 'chatter' })),
    [{ id: 7, user: bot, body: marker + ' old report' }],
  ],
  failing: null,
}[scenario];
const github = {
  rest: { issues: {
    listComments: 'listComments',
    updateComment: async (args) => { calls.push(['update', args.comment_id]); },
    createComment: async () => { calls.push(['create']); },
  } },
  paginate: async () => {
    if (pages === null) throw new Error('boom');
    return pages.flat();
  },
};
const context = { repo: { owner: 'o', repo: 'r' }, issue: { number: 5 } };
const core = { warning: (m) => warnings.push(m), notice: () => {} };
process.env.REPORT_FILE = '/nonexistent';
process.env.PR_NUMBER = '5';
const AsyncFunction = (async () => {}).constructor;
new AsyncFunction('github', 'context', 'core', 'require', body)(github, context, core, require)
  .then(() => console.log(JSON.stringify({ calls, warnings })))
  .catch((e) => console.log(JSON.stringify({ thrown: e.message })));
"""


def _scripts():
    found = []
    action = YAML(typ="safe").load(Path(__file__).resolve().parents[1].joinpath("action.yml").read_text())
    for step in action["runs"]["steps"]:
        if "github-script" in str(step.get("uses", "")) and "listComments" in step["with"]["script"]:
            found.append(("action.yml", step["with"]["script"], "<!-- tridelphi -->"))
    for name, text, marker in (
        ("init workflow", WORKFLOW, "<!-- tridelphi -->"),
        ("init app workflow", APP_WORKFLOW, "<!-- tridelphi-expose -->"),
    ):
        doc = YAML(typ="safe").load(text)
        for job in doc["jobs"].values():
            for step in job.get("steps", []):
                if (isinstance(step, dict) and "github-script" in str(step.get("uses", ""))
                        and "listComments" in step["with"]["script"]):
                    found.append((name, step["with"]["script"], marker))
    assert len(found) == 3, [f[0] for f in found]
    return found


def _run(body: str, marker: str, scenario: str) -> dict:
    out = subprocess.run(
        [NODE, "-e", HARNESS, json.dumps([body, marker, scenario])],
        capture_output=True, text=True, timeout=60, check=True,
    ).stdout
    return json.loads(out.strip().splitlines()[-1])


@pytest.mark.parametrize("name,body,marker", _scripts(), ids=lambda v: v if isinstance(v, str) and len(v) < 30 else "")
def test_sticky_comment_is_ours_all_pages_and_never_fatal(name, body, marker):
    planted = _run(body, marker, "planted")
    assert planted == {"calls": [["create"]], "warnings": []}, f"{name}: edited a stranger's comment"
    second = _run(body, marker, "second_page")
    assert second["calls"] == [["update", 7]], f"{name}: missed our comment on page two"
    failing = _run(body, marker, "failing")
    assert "thrown" not in failing and failing["warnings"], f"{name}: an API error must warn, not throw"
