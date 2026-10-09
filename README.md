# ShipGate

A **single pre-publish gate** you run (or wire as a git `pre-push` hook) before any repo or folder goes public. It fails closed: a hard finding blocks the push, so an automated or half-asleep `git push` can't leak a secret or ship something un-licensed.

Four checks, each must pass:

| Gate | Checks |
|---|---|
| **(a) gitleaks** | filesystem **+ git history** secret scan |
| **(b) trufflehog** | verified-secrets scan, filesystem + git history |
| **(c) LICENSE** | a `LICENSE`/`COPYING` file exists and its text names a known license (warns if an SPDX line sits inside it, since that can stop GitHub naming the license), and **no raw `.env`** snuck in |
| **(d) attribution** | if content is flagged derivative (`DERIVATIVE.md`, `derivative: true`, or `responding-to:` frontmatter) it requires a `CREDIT.md`/`ATTRIBUTION.md`; nudges for an AI-assist disclosure |

If a scanner isn't installed, ShipGate **warns and runs the rest; it never silently passes.**

## Why

Secrets-in-git-history is the #1 way OSS releases leak credentials, and it survives even after you delete the file from `HEAD`. ShipGate scans history as well as the working tree, and bundles the boring-but-mandatory license/`.env`/attribution checks into one exit code so "is this safe to publish?" becomes a single command.

## Install

```bash
brew install gitleaks trufflehog        # the scanners (ShipGate warns if missing)
git clone https://github.com/Lucface/shipgate.git
cp shipgate/ship-gate.sh ~/.local/bin/  # or anywhere on PATH
```

## Use

```bash
ship-gate.sh .                  # gate the current repo (scans working tree + history)
ship-gate.sh ./some/folder      # gate a plain directory
ship-gate.sh ./a-single-file.md # gate a file (scans its parent dir)
```

Exit `0` = safe to publish · nonzero = blocked, with each `[FAIL]` to fix.

### Wire it as a pre-push hook (recommended)

From inside any repo:

```bash
GATE="$(command -v ship-gate.sh)"
H="$(git rev-parse --git-dir)/hooks/pre-push"
printf '#!/usr/bin/env bash\nexec "%s" "$(git rev-parse --show-toplevel)"\n' "$GATE" > "$H"
chmod +x "$H"
```

Now `git push` runs the gate first and aborts on any hard finding. (Note: `--no-verify` skips the hook, so the gate catches mistakes and cannot stop a deliberate bypass.)

## License

MIT. See [LICENSE](./LICENSE). By [@Lucface](https://github.com/Lucface). Extracted clean from a larger private release pipeline.
