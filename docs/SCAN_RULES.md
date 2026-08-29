# Pre-install scan rules — `tridelphi scan`

`tridelphi scan <target>` reads someone else's code **before** you install it and
grades what it finds against the shapes of real 2026 supply-chain attacks. It
reads files; it never executes them.

This is a different rule family from the [Rule-of-Two workflow rules](RULES.md).
Those ask "is *my* CI safe to run?"; these ask "is *this thing I'm about to
install* safe to run?"

## The severity dial: install context

The same line means different things in different files, so every finding carries
a context and grades against it:

| Context | What it is | `curl \| bash` here is |
|---|---|---|
| **install** | runs without you choosing to: npm `postinstall`, `setup.py`, `.envrc`, VS Code `folderOpen` tasks, shipped git hooks | **critical** |
| **agent** | an AI assistant loads it as instructions or executes it: `SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.mcp.json` | **critical** |
| **code** | ordinary source in the tree | **warning** |
| **doc** | a README or guide — it does not run itself | **warning** (the Homebrew shape) |

A clean result means *no known-bad patterns in the source and config we read*. It
is never a safety certificate: a static scan cannot judge a compiled binary,
sandbox anything, or predict what a server sends tomorrow. The report says so on
every run.

## Categories

### I — install-time execution

Code wired to run the moment you install or open the folder.

- `install-hook-downloader` (**critical**) — an npm `preinstall`/`install`/`postinstall`/`prepare` script that reaches for the network or an encoder. The single most-used malware-delivery slot in the JS ecosystem. Benign native-build commands (`node-gyp rebuild`, `prisma generate`, `husky`, …) are recognised and not flagged.
- `install-hook` (**note**) — a lifecycle script that is *not* obviously malicious. Most are build steps; all deserve one read. A local script it calls is pulled into the scan and escalated to install context.
- `direnv-autorun` (**note**) — a `.envrc`; with direnv it runs on `cd`.
- `shipped-git-hook` (**warning**) — a live hook in `.git/hooks`. A normal clone never carries one, so an archive that ships one did it on purpose.

### D — download-and-run

Fetch-and-execute: the server decides what runs on your machine.

- `download-and-execute` (**critical** in install/agent/untrustworthy contexts) — `curl \| bash`, PowerShell download cradles, `fetch`→`chmod +x`→run, Python/JS download-then-`exec`/`eval`. "Untrustworthy" = a raw-IP, shortener, or throwaway-host source, which gates even in a doc.
- `download-and-execute-doc` (**warning**) — the same shape in documentation. Real projects do this (it is how you install Homebrew), and it is still the copycat-installer shape, so it is named, not silenced.

### O — obfuscation

Encoding a command has one honest use at install time: none.

- `encoded-execution` (**critical**) — base64-piped-to-shell, `eval(atob(…))`, `exec(base64.b64decode(…))`, PowerShell `-EncodedCommand`, `eval(String.fromCharCode(…))`.
- `encoded-execution-doc` (**warning**) — the same, described in prose. A README explaining `eval(atob())` is documentation, not a dropper.
- `invisible-characters` (**critical**) — zero-width or bidirectional-override Unicode in a script or agent file. You read one thing; a model or interpreter reads another. A leading BOM is exempt.
- `opaque-blob` (**warning**) — a long base64 literal in an install or agent file. Maybe an asset, maybe a payload; you can't tell without decoding it.

### C — credential & wallet reach

Reads of the things worth stealing.

- `credential-reach` (**critical**) — a path-shaped reference to `~/.ssh`, cloud credentials, browser login/cookie stores, crypto wallets, or the keychain, *inside a file that runs at install, that an assistant loads, or that also sends data over the network*. A read plus a send is exfiltration's exact shape.
- `credential-reach-code` (**warning**) — the same reference in ordinary code that neither auto-runs nor phones home. Some tools have a legitimate reason; most don't.

### A — poisoned agent files

Files an assistant treats as instructions or executes.

- `covert-instruction` (**critical**) — a secrecy instruction ("silently", "do not tell the user") paired with an action (download, install, credential access). The poisoned-skill shape: the assistant is told to act and not tell you.
- `hidden-comment-instruction` (**critical**) — an imperative inside an HTML comment: invisible in any rendered view, read by a model like any other text.
- `agent-config-downloader` (**critical**) — a command in `.mcp.json` / hooks / VS Code tasks that reaches for the network or an encoder, run automatically when the config loads.
- `editor-autorun-task` (**warning**) — a VS Code task that runs on `folderOpen`: opening the folder is enough to execute it.
- `agent-config-command` / `secrecy-language` (**note** / **warning**) — a command an assistant loads, or secrecy phrasing with no adjacent action. Surfaced for a read, not gated.

### L — dishonest links

The copycat-site trick, mechanized.

- `link-text-mismatch` (**critical**) — Markdown link text names one domain; the URL goes to another. (A dotted *package* or *file* name like `ruamel.yaml` in the text is not a domain claim and is not flagged.)
- `throwaway-code-host` (**critical** in install/code) — code fetched from a paste site or chat CDN. Legitimate software does not distribute itself from these.
- `shortened-link` / `raw-ip-url` / `lookalike-domain` (**warning**) — a link that hides its destination, points at a bare IP, or uses punycode / non-ASCII characters.

## Targets and the network

- **A directory** — a cloned repo or unpacked download. Pure file reads.
- **An archive** — `.tgz` / `.tar.gz` / `.zip` / `.whl`, extracted to a temp dir first. Path-traversal and zip-slip entries are refused — an archive built to escape its extraction directory is malicious by construction, and that refusal is itself the verdict.
- **`npm:<pkg>`** — `npm pack` downloads the published tarball and, unlike `npm install`, runs none of its scripts.
- **`pypi:<pkg>`** — a plain HTTPS GET against PyPI's JSON API, never `pip download` (which can execute a hostile `setup.py` just to resolve metadata).

The two registry forms are the tool's only network use. They download without
installing or executing, and they announce it on stderr before connecting.
