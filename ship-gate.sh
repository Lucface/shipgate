#!/usr/bin/env bash
# =============================================================================
# ship-gate.sh: ShipGate, a standalone pre-publish and pre-push gate.
# Runs secret scans + a LICENSE check + an attribution check; nonzero exit = block.
# Usage:   ship-gate.sh <path-or-jobdir>
#
# Gates (all must pass; exit nonzero = block):
#   (a) gitleaks dir/git: secret scan on filesystem + git history
#   (b) trufflehog filesystem/git: verified-secrets scan + git history
#   (c) LICENSE: present, holds a known license's grant text, no SPDX line inside it
#   (d) credit-check: flag un-attributed derivative content
#
# Behavior:
#   - If a scanner is missing at runtime: WARN + run the others, NEVER silently pass
#   - Any hard finding -> nonzero exit (the caller decides what to do next)
#   - Nothing auto-publishes; this is a GATE, not a publisher
#
# After all gates pass, this script exits 0. Wire it as a git pre-push hook (see the
# installer at the bottom of this file) or call it from your own release flow.
# =============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
pass()  { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET} $*"; HARD_FAIL=1; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
info()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
header(){ echo -e "\n${BOLD}══ $* ══${RESET}"; }

HARD_FAIL=0
SCANNERS_MISSING=()

# ── Argument validation ───────────────────────────────────────────────────────
if [ $# -lt 1 ]; then
  echo "Usage: ship-gate.sh <path-or-jobdir>"
  echo "  <path-or-jobdir>  Directory or file to scan. For git repos, git history"
  echo "                    is also scanned."
  exit 1
fi

TARGET="$1"

if [ ! -e "$TARGET" ]; then
  echo -e "${RED}ERROR:${RESET} Target not found: $TARGET"
  exit 1
fi

# Resolve to absolute path
TARGET="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"

# If target is a file, scan its parent dir (git repo detection still works)
if [ -f "$TARGET" ]; then
  SCAN_DIR="$(dirname "$TARGET")"
  SINGLE_FILE="$TARGET"
else
  SCAN_DIR="$TARGET"
  SINGLE_FILE=""
fi

echo -e "${BOLD}=== SHIPGATE: PRE-PUBLISH GATE ===${RESET}"
echo -e "Target:   $TARGET"
echo -e "Scan dir: $SCAN_DIR"
echo ""

# ── Detect git repo ───────────────────────────────────────────────────────────
IS_GIT=0
GIT_ROOT=""
if git -C "$SCAN_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
  IS_GIT=1
  GIT_ROOT="$(git -C "$SCAN_DIR" rev-parse --show-toplevel)"
  info "Git repo detected: $GIT_ROOT"
else
  info "Not a git repo, so the history scan is skipped"
fi

# =============================================================================
# GATE (a): gitleaks, filesystem secret scan
# =============================================================================
header "GATE (a): gitleaks filesystem scan"

GITLEAKS_BIN="$(command -v gitleaks 2>/dev/null || true)"

if [ -z "$GITLEAKS_BIN" ]; then
  warn "gitleaks not found in PATH. Install: brew install gitleaks"
  warn "Skipping gitleaks scan; a skipped scan is a WARN."
  SCANNERS_MISSING+=("gitleaks")
else
  info "gitleaks $(gitleaks version 2>/dev/null || echo '(version unknown)')"

  # macOS BSD mktemp only substitutes XXXXXX when it is the TRAILING part of the
  # template (a ".txt" suffix makes it a literal filename → collisions on re-run).
  # Use the portable `-t` form (works on both BSD/macOS and GNU/Linux).
  GITLEAKS_OUT="$(mktemp -t ship-gate-gitleaks)"

  # gitleaks v8 CLI: `gitleaks git <path>` for repos, `gitleaks dir <path>` for plain dirs.
  # (The old `detect --source --no-git` syntax was removed in v8.x.)
  _gitleaks_show_findings() {
    local out_file="$1"
    # Output is JSON-lines in v8 dir mode, JSON array in git mode; handle both
    python3 - "$out_file" <<'PYEOF'
import json, sys
raw = open(sys.argv[1]).read().strip()
if not raw:
    sys.exit(0)
try:
    findings = json.loads(raw)  # JSON array (git mode)
    if not isinstance(findings, list):
        findings = [findings]
except json.JSONDecodeError:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try: findings.append(json.loads(line))
            except Exception: pass
for i, f in enumerate(findings[:5], 1):
    rule  = f.get('RuleID', 'unknown')
    file_ = f.get('File', f.get('file', 'unknown'))
    line  = f.get('StartLine', f.get('line', '?'))
    match = str(f.get('Match', f.get('match', '')))[:60]
    print(f"  {i}. [{rule}] {file_}:{line}  →  {match}...")
if len(findings) > 5:
    print(f"  ... and {len(findings) - 5} more.")
PYEOF
  }

  if [ $IS_GIT -eq 1 ]; then
    # Scan git repo (staged + working tree + history)
    if gitleaks git \
        --no-banner \
        --redact \
        --report-path "$GITLEAKS_OUT" \
        --report-format json \
        "$GIT_ROOT" 2>&1 | grep -vE '^$|^time='; then
      pass "gitleaks git: no secrets found in repo"
    else
      fail "gitleaks git: secret(s) detected in repo/history"
      if [ -s "$GITLEAKS_OUT" ]; then
        echo -e "${RED}  Findings:${RESET}"
        _gitleaks_show_findings "$GITLEAKS_OUT"
      fi
    fi
  else
    # Non-git: filesystem dir scan
    if gitleaks dir \
        --no-banner \
        --redact \
        --report-path "$GITLEAKS_OUT" \
        --report-format json \
        "$SCAN_DIR" 2>&1 | grep -vE '^$|^time='; then
      pass "gitleaks dir: no secrets found"
    else
      fail "gitleaks dir: secret(s) detected"
      if [ -s "$GITLEAKS_OUT" ]; then
        echo -e "${RED}  Findings:${RESET}"
        _gitleaks_show_findings "$GITLEAKS_OUT"
      fi
    fi
  fi

  rm -f "$GITLEAKS_OUT"
fi

# =============================================================================
# GATE (b): trufflehog, verified secrets (filesystem + git history)
# =============================================================================
header "GATE (b): trufflehog verified-secrets scan"

TRUFFLEHOG_BIN="$(command -v trufflehog 2>/dev/null || true)"

if [ -z "$TRUFFLEHOG_BIN" ]; then
  warn "trufflehog not found in PATH. Install: brew install trufflehog"
  warn "Skipping trufflehog scan; a skipped scan is a WARN."
  SCANNERS_MISSING+=("trufflehog")
else
  info "trufflehog $(trufflehog --version 2>&1 | head -1)"

  # Portable mktemp (-t); see the note in GATE (a) above about macOS BSD behavior.
  TRUFFLE_FS_OUT="$(mktemp -t ship-gate-truffle-fs)"
  TRUFFLE_GIT_OUT="$(mktemp -t ship-gate-truffle-git)"
  TRUFFLE_FAILED=0

  # (b1) filesystem scan
  info "Running trufflehog filesystem scan..."
  if trufflehog filesystem \
      --only-verified \
      --no-update \
      --json \
      "$SCAN_DIR" \
      > "$TRUFFLE_FS_OUT" 2>/dev/null; then
    FS_FINDINGS="$(wc -l < "$TRUFFLE_FS_OUT" | tr -d ' ')"
    if [ "$FS_FINDINGS" -eq 0 ] || [ ! -s "$TRUFFLE_FS_OUT" ]; then
      pass "trufflehog filesystem: no verified secrets"
    else
      fail "trufflehog filesystem: $FS_FINDINGS verified secret(s)"
      head -3 "$TRUFFLE_FS_OUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        dtype = d.get('DetectorName','?')
        file_ = d.get('SourceMetadata',{}).get('Data',{}).get('Filesystem',{}).get('file','?')
        print(f'  - [{dtype}] {file_}')
    except Exception:
        print(f'  - {line[:80]}')
"
      TRUFFLE_FAILED=1
    fi
  else
    # trufflehog exits nonzero when it finds results too
    FS_FINDINGS="$(wc -l < "$TRUFFLE_FS_OUT" | tr -d ' ')"
    if [ "$FS_FINDINGS" -gt 0 ]; then
      fail "trufflehog filesystem: verified secrets found"
      head -3 "$TRUFFLE_FS_OUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        dtype = d.get('DetectorName','?')
        file_ = d.get('SourceMetadata',{}).get('Data',{}).get('Filesystem',{}).get('file','?')
        print(f'  - [{dtype}] {file_}')
    except Exception:
        print(f'  - {line[:80]}')
"
      TRUFFLE_FAILED=1
    else
      pass "trufflehog filesystem: no verified secrets"
    fi
  fi

  # (b2) git history scan (only if it's a git repo)
  if [ $IS_GIT -eq 1 ]; then
    info "Running trufflehog git history scan..."
    if trufflehog git \
        --only-verified \
        --no-update \
        --json \
        "file://$GIT_ROOT" \
        > "$TRUFFLE_GIT_OUT" 2>/dev/null; then
      GIT_FINDINGS="$(wc -l < "$TRUFFLE_GIT_OUT" | tr -d ' ')"
      if [ "$GIT_FINDINGS" -eq 0 ] || [ ! -s "$TRUFFLE_GIT_OUT" ]; then
        pass "trufflehog git history: no verified secrets"
      else
        fail "trufflehog git history: $GIT_FINDINGS verified secret(s) in history"
        head -3 "$TRUFFLE_GIT_OUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        dtype = d.get('DetectorName','?')
        commit = d.get('SourceMetadata',{}).get('Data',{}).get('Git',{}).get('commit','?')[:8]
        file_  = d.get('SourceMetadata',{}).get('Data',{}).get('Git',{}).get('file','?')
        print(f'  - [{dtype}] commit {commit}  {file_}')
    except Exception:
        print(f'  - {line[:80]}')
"
      fi
    else
      GIT_FINDINGS="$(wc -l < "$TRUFFLE_GIT_OUT" | tr -d ' ')"
      if [ "$GIT_FINDINGS" -gt 0 ]; then
        fail "trufflehog git history: verified secrets found in history"
        TRUFFLE_FAILED=1
      else
        pass "trufflehog git history: no verified secrets"
      fi
    fi
  fi

  rm -f "$TRUFFLE_FS_OUT" "$TRUFFLE_GIT_OUT"
fi

# =============================================================================
# GATE (c): LICENSE present + SPDX header check
# =============================================================================
header "GATE (c): LICENSE + SPDX"

# Determine scan root (use git root for repos, else target dir)
if [ $IS_GIT -eq 1 ]; then
  ROOT_FOR_LICENSE="$GIT_ROOT"
else
  ROOT_FOR_LICENSE="$SCAN_DIR"
fi

# (c1) LICENSE file present
LICENSE_FILE=""
for candidate in LICENSE LICENSE.txt LICENSE.md COPYING; do
  if [ -f "$ROOT_FOR_LICENSE/$candidate" ]; then
    LICENSE_FILE="$ROOT_FOR_LICENSE/$candidate"
    break
  fi
done

if [ -n "$LICENSE_FILE" ]; then
  # GitHub names a license by matching LICENSE against the license's known text, so an
  # extra line (an SPDX header included) can stop it naming the license. The SPDX id
  # belongs in package metadata or per-file headers; LICENSE holds the license text only.
  # A license is recognized by its grant sentence, so a file holding only a license's name
  # (which grants nothing) is never a pass.
  SPDX_ID="$(grep -i 'SPDX-License-Identifier' "$LICENSE_FILE" | head -1 | sed 's/.*SPDX-License-Identifier://;s/[[:space:]]//g' || true)"
  LICENSE_TEXT=""
  if [ -r "$LICENSE_FILE" ]; then
    LICENSE_TEXT="$(tr -s '[:space:]' ' ' < "$LICENSE_FILE" || true)"
  fi
  VERBATIM="Everyone is permitted to copy and distribute verbatim copies"
  KNOWN=""
  # The long licenses come first: their files often append third-party MIT or BSD
  # notices, and the first matching arm names the license.
  case "$LICENSE_TEXT" in
    *"Apache License"*"Version 2.0, January 2004"*"Grant of Copyright License"*) KNOWN="Apache-2.0" ;;
    *"GNU AFFERO GENERAL PUBLIC LICENSE"*"$VERBATIM"*) KNOWN="AGPL" ;;
    *"GNU LESSER GENERAL PUBLIC LICENSE"*"$VERBATIM"*) KNOWN="LGPL" ;;
    *"GNU GENERAL PUBLIC LICENSE"*"$VERBATIM"*) KNOWN="GPL" ;;
    *"Mozilla Public License Version 2.0"*"1. Definitions"*) KNOWN="MPL-2.0" ;;
    *"CC0 1.0 Universal"*"Statement of Purpose"*) KNOWN="CC0-1.0" ;;
    *"Creative Commons"*"By exercising the Licensed Rights"*) KNOWN="Creative Commons" ;;
    *"Permission is hereby granted, free of charge, to any person obtaining a copy"*) KNOWN="MIT" ;;
    *"Permission to use, copy, modify, and/or distribute this software for any purpose"*) KNOWN="ISC" ;;
    *"Redistribution and use in source and binary forms, with or without modification"*) KNOWN="BSD" ;;
    *"This is free and unencumbered software released into the public domain"*) KNOWN="Unlicense" ;;
  esac
  if [ -n "$KNOWN" ]; then
    pass "LICENSE found: $KNOWN, recognized by its grant text"
    if [ -n "$SPDX_ID" ]; then
      warn "LICENSE also carries 'SPDX-License-Identifier: $SPDX_ID'. GitHub matches the license text, so that line can stop it naming the license. Move the id to package metadata or file headers and keep $LICENSE_FILE to the license text."
    fi
    # MIT, ISC and BSD put the copyright line on top; Apache and the GPLs keep template
    # placeholders in their own how-to-apply appendix, so only the first three are checked.
    case "$KNOWN" in
      MIT|ISC|BSD)
        if grep -qiE '\[year\]|\[fullname\]|<year>|<copyright holders?>|<owner>' "$LICENSE_FILE"; then
          warn "LICENSE still holds template placeholders such as [year] or [fullname]. Fill in the year and the copyright holder in $LICENSE_FILE"
        fi
        ;;
    esac
  elif [ ! -r "$LICENSE_FILE" ]; then
    warn "LICENSE exists but cannot be read. Check the permissions on $LICENSE_FILE"
  elif [ -n "$SPDX_ID" ]; then
    warn "LICENSE names 'SPDX-License-Identifier: $SPDX_ID' but holds no license text this gate recognizes. Put the license's full text in $LICENSE_FILE"
  else
    warn "LICENSE found, but its text matches no license this gate knows. Verify the license in $LICENSE_FILE"
  fi
else
  fail "No LICENSE file found in $ROOT_FOR_LICENSE. Every public ship needs a license."
  info "Quick fix for MIT: copy the text at https://choosealicense.com/licenses/mit/ into LICENSE and fill in the year and your name (with gh signed in: gh api licenses/mit --jq .body > LICENSE, then replace [year] and [fullname])."
fi

# (c2) Check for .env files accidentally included (defense-in-depth)
ENV_FILES="$(find "$SCAN_DIR" -maxdepth 4 -name '.env' -not -path '*/.git/*' -not -name '.env.example' 2>/dev/null | head -5 || true)"
if [ -n "$ENV_FILES" ]; then
  fail "Raw .env file(s) found (not .env.example):"
  echo "$ENV_FILES" | while IFS= read -r f; do echo "  $f"; done
else
  pass "No raw .env files found"
fi

# =============================================================================
# GATE (d): Credit-check, derivative content attribution
# =============================================================================
header "GATE (d): Credit / Attribution check"

# Look for CREDIT.md, ATTRIBUTION.md, or NOTICE files
CREDIT_FILE=""
for candidate in CREDIT.md ATTRIBUTION.md CREDITS.md NOTICE NOTICE.md; do
  if [ -f "$ROOT_FOR_LICENSE/$candidate" ]; then
    CREDIT_FILE="$ROOT_FOR_LICENSE/$candidate"
    break
  fi
done

# Check if there's a sidecar flagging derivative status
# Convention: any file named *.derivative, DERIVATIVE.md, or containing
# "derivative: true" / "source: " frontmatter in the job dir signals attribution required.
DERIVATIVE_SIDECAR=""
if [ -d "$SCAN_DIR" ]; then
  DERIVATIVE_SIDECAR="$(find "$SCAN_DIR" -maxdepth 2 \( -name '*.derivative' -o -name 'DERIVATIVE.md' \) 2>/dev/null | head -1 || true)"

  # Also look for YAML/frontmatter "derivative: true" in any markdown file
  if [ -z "$DERIVATIVE_SIDECAR" ]; then
    DERIVATIVE_SIDECAR="$(grep -rlE '^[[:space:]]*derivative:[[:space:]]*true' "$SCAN_DIR" --include='*.md' --include='*.yaml' --include='*.yml' 2>/dev/null | head -1 || true)"
  fi
fi

# Also flag response pieces: "source-author:" / "responding-to:" frontmatter signals
# content derived from someone else's structure or argument.
RESPONSE_PIECE=""
if [ -d "$SCAN_DIR" ]; then
  RESPONSE_PIECE="$(grep -rlE '^[[:space:]]*(responding-to|source-author|based-on):' "$SCAN_DIR" --include='*.md' 2>/dev/null | head -1 || true)"
fi

if [ -n "$DERIVATIVE_SIDECAR" ]; then
  # Derivative flagged: check that CREDIT/ATTRIBUTION exists
  if [ -n "$CREDIT_FILE" ]; then
    # Verify the credit file is non-empty and mentions attribution
    if grep -qiE 'source|attribution|responding to|riff|based on|credit' "$CREDIT_FILE" 2>/dev/null; then
      pass "Derivative sidecar found + attribution present in $CREDIT_FILE"
    else
      fail "Derivative sidecar found but $CREDIT_FILE appears empty or lacks attribution text. Add source link + 'responding to / riffing on' framing."
    fi
  else
    fail "Derivative content flagged ($DERIVATIVE_SIDECAR) but no CREDIT.md / ATTRIBUTION.md found."
    fail "Derivative content requires attribution BEFORE publish."
    info "Fix: create $ROOT_FOR_LICENSE/ATTRIBUTION.md with source link + your distinct added value."
  fi
elif [ -n "$RESPONSE_PIECE" ]; then
  if [ -n "$CREDIT_FILE" ]; then
    pass "Response piece detected + attribution file exists ($CREDIT_FILE)"
  else
    warn "File with 'responding-to:/source-author:' found ($RESPONSE_PIECE) but no ATTRIBUTION.md."
    warn "If this derives from someone else's structure/argument, add ATTRIBUTION.md before publish."
    # This is a WARN because the frontmatter key alone is not definitive
  fi
else
  # No derivative marker found
  if [ -n "$CREDIT_FILE" ]; then
    pass "Attribution file present: $CREDIT_FILE (no derivative sidecar required)"
  else
    # Check README for AI-assist disclosure (pipeline requires it for substantial AI use)
    README_FILE=""
    for candidate in README.md README.txt README; do
      if [ -f "$ROOT_FOR_LICENSE/$candidate" ]; then
        README_FILE="$ROOT_FOR_LICENSE/$candidate"
        break
      fi
    done

    if [ -n "$README_FILE" ] && grep -qiE 'ai.assist|claude|gpt|generated|co-authored' "$README_FILE" 2>/dev/null; then
      pass "AI-assist disclosure detected in $README_FILE"
    else
      warn "No ATTRIBUTION.md and no AI-assist disclosure found in README."
      warn "If this work is substantially AI-assisted, add a disclosure line to README."
      warn "(This is a WARN; only fails if derivative sidecar is present.)"
    fi
  fi
fi

# =============================================================================
# Summary
# =============================================================================
header "SUMMARY"

if [ ${#SCANNERS_MISSING[@]} -gt 0 ]; then
  warn "Missing scanners (install for full coverage): ${SCANNERS_MISSING[*]}"
  warn "Install all: brew install gitleaks trufflehog"
fi

if [ $HARD_FAIL -eq 0 ]; then
  echo -e "\n${GREEN}${BOLD}GATE: PASS${RESET}. All hard checks passed. Safe to queue for human review."
  echo ""
  echo "  Next step: queue for human review before publishing."
  echo ""
  exit 0
else
  echo -e "\n${RED}${BOLD}GATE: BLOCKED${RESET}. Fix all [FAIL] items above before publishing."
  echo ""
  echo "  Hard failures prevent publish. Fix each [FAIL] item, then re-run:"
  echo "    ship-gate.sh $TARGET"
  echo ""
  exit 1
fi

# =============================================================================
# PRE-PUSH HOOK INSTALLER (run this block once per repo to wire the gate)
# =============================================================================
# To install ship-gate as a git pre-push hook in any repo, run:
#
#   SHIP_GATE="ship-gate.sh"
#   HOOK="$(git rev-parse --git-dir)/hooks/pre-push"
#   cat > "$HOOK" <<'HOOK_EOF'
#   #!/usr/bin/env bash
#   # ShipGate pre-push gate
#   # Blocks push if secrets, missing LICENSE, or un-attributed derivatives are found.
#   REPO_ROOT="$(git rev-parse --show-toplevel)"
#   GATE="ship-gate.sh"
#   if [ ! -x "$GATE" ]; then
#     echo "WARN: ship-gate.sh not found at $GATE, skipping the gate (install risk)"
#     exit 0
#   fi
#   exec "$GATE" "$REPO_ROOT"
#   HOOK_EOF
#   chmod +x "$HOOK"
#   echo "Pre-push hook installed at $HOOK"
#
# One-liner (paste into any repo):
#   GATE="ship-gate.sh"; H="$(git rev-parse --git-dir)/hooks/pre-push"; printf '#!/usr/bin/env bash\nexec "%s" "$(git rev-parse --show-toplevel)"\n' "$GATE" > "$H" && chmod +x "$H" && echo "Hook installed: $H"
# =============================================================================
