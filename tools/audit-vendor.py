#!/usr/bin/env python3
"""
tools/audit-vendor.py -- supply-chain pattern scan for the vendored dependency bundle.

Usage:
    python3 tools/audit-vendor.py                 # scans vendor/deps.js and vendor/jsqr.js
    python3 tools/audit-vendor.py <file> [file...] # scans specific files instead

Exit 0 = clean (only allowlisted hits, or none). Exit 1 = a hard-fail pattern matched a line
that is not covered by the ALLOWLIST below; the offending file:line:pattern is printed.

This is a heuristic line/regex scanner over the built output, not a JS parser. It exists to
catch a network/storage/eval primitive appearing in code this page will actually load and run
with WIF private keys in memory -- not to be a general-purpose static analyzer. Every pattern
below was chosen from the task spec and checked by hand against the real vendor/deps.js and
vendor/jsqr.js at least once (see ALLOWLIST comments for what was actually found and why each
allowlisted line is safe). If you add a new dependency and the audit starts failing, INSPECT
the matched line yourself before touching ALLOWLIST -- a reachable fetch()/postMessage()/etc.
is a real problem to report, not something to allowlist away.

Comment handling: a line is treated as "comment-only" (and skipped entirely) if it is inside a
/* ... */ block (tracked across lines) or its trimmed text starts with `//` or `*` (a JSDoc/
block-comment continuation line). This correctly classifies both esbuild's trailing "Bundled
license information" block comment and short `// https://...` explanatory comments, without
hiding the one real non-comment URL hit this scan actually found (an `xmlns="http://..."`
string inside bbqr's unused SVG-render helper -- see ALLOWLIST). Known limitation: a comment
that starts after code on the same line (`foo(); /* like this */`) is not detected as partially
a comment -- the whole line is still scanned. That has not produced a false positive against
the actual bundle; if it ever does, inspect it rather than papering over it with a broader skip.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILES = [ROOT / "vendor" / "deps.js", ROOT / "vendor" / "jsqr.js"]

# --------------------------------------------------------------------------------------
# pattern table (exactly the patterns named in the task spec)
# --------------------------------------------------------------------------------------
# Lookbehind `(?<![\w$])` excludes matches inside a longer identifier (e.g. `require_eval(`
# does not match `eval(`) but deliberately does NOT exclude a preceding `.` -- `window.fetch(`
# or `self.eval(` must still be caught, since those are exactly how a real call would look.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("fetch(",           re.compile(r'(?<![\w$])fetch\s*\(')),
    ("XMLHttpRequest",   re.compile(r'XMLHttpRequest')),
    ("WebSocket",        re.compile(r'(?<![\w$])WebSocket\b')),
    ("sendBeacon",       re.compile(r'(?<![\w$])sendBeacon\s*\(')),
    ("EventSource",      re.compile(r'(?<![\w$])EventSource\b')),
    ("eval(",            re.compile(r'(?<![\w$])eval\s*\(')),
    ("new Function",     re.compile(r'\bnew\s+Function\s*\(')),
    ("dynamic import(",  re.compile(r'(?<![\w$])import\s*\(')),
    ("document.cookie",  re.compile(r'document\.cookie')),
    ("localStorage",     re.compile(r'(?<![\w$])localStorage\b')),
    ("sessionStorage",   re.compile(r'(?<![\w$])sessionStorage\b')),
    ("indexedDB",        re.compile(r'(?<![\w$])indexedDB\b')),
    ("postMessage(",     re.compile(r'(?<![\w$])postMessage\s*\(')),
    ("serviceWorker",    re.compile(r'\bserviceWorker\b')),
    ("<script",          re.compile(r'<script\b', re.IGNORECASE)),
    ("location.href =",  re.compile(r'location\.href\s*=(?!=)')),
    ("http(s):// URL",   re.compile(r'https?://[^\s"\'`)]+')),
]

# --------------------------------------------------------------------------------------
# allowlist -- every entry requires the exact matched line text + a one-line justification.
# Matched by (pattern label, substring containment in the offending line), not by line number,
# so it survives incidental reformatting across rebuilds; a genuinely different line requires a
# genuinely new (and re-reviewed) allowlist entry.
# --------------------------------------------------------------------------------------
ALLOWLIST: list[dict[str, str]] = [
    {
        "label": "http(s):// URL",
        "match": 'xmlns="http://www.w3.org/2000/svg"',
        "justification": (
            "XML namespace URI string literal inside bbqr's SVG-render helper. This app only "
            "calls splitQRs/joinQRs -- bbqr's render()/SVG path is unused dead code that "
            "esbuild's tree-shaking did not eliminate (it shares a module scope with the "
            "exports we do use). An xmlns value is never fetched or navigated to by a browser; "
            "it is purely a namespace identifier string."
        ),
    },
    {
        "label": "localStorage",
        "match": "if (!global.localStorage) return false;",
        "justification": (
            "util-deprecate (pulled transitively via bip32@4.0.0 -> wif@2.0.6 -> "
            "bs58check@2.1.2 -> create-hash -> md5.js -> hash-base -> readable-stream@2) reads "
            "a noDeprecation/throwDeprecation/traceDeprecation debug flag, guarded by "
            "try/catch, from inside the wrapper deprecate() returns -- which only runs if a "
            "deprecated readable-stream API is actually called. This app never calls one. "
            "Read-only; nothing is written or exfiltrated."
        ),
    },
    {
        "label": "localStorage",
        "match": "var val = global.localStorage[name];",
        "justification": "Same util-deprecate config() read as the entry above.",
    },
]


def is_allowlisted(label: str, line_text: str) -> bool:
    return any(entry["label"] == label and entry["match"] in line_text for entry in ALLOWLIST)


# --------------------------------------------------------------------------------------
# scanner
# --------------------------------------------------------------------------------------

def scan_file(path: Path) -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []
    in_block_comment = False
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        line_is_comment = False

        if in_block_comment:
            line_is_comment = True
            if "*/" in line:
                in_block_comment = False
        elif stripped.startswith("//") or stripped.startswith("*"):
            line_is_comment = True
        elif stripped.startswith("/*"):
            line_is_comment = True
            if "*/" not in stripped[2:]:
                in_block_comment = True

        if line_is_comment:
            continue

        for label, pattern in PATTERNS:
            if pattern.search(line):
                # Keep the FULL line for allowlist matching (a long minified line can easily put
                # the actual match past any fixed display truncation); only the printed excerpt
                # is shortened, and it's built from the full text so it still centers on the hit.
                findings.append((path, lineno, label, line.strip()))

    return findings


def main() -> None:
    args = sys.argv[1:]
    paths = [Path(a) for a in args] if args else DEFAULT_FILES

    missing = [p for p in paths if not p.exists()]
    if missing:
        for p in missing:
            print(f"audit-vendor: file not found: {p}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[tuple[Path, int, str, str]] = []
    for p in paths:
        all_findings.extend(scan_file(p))

    hard_fails = []
    allowlisted = 0
    for path, lineno, label, text in all_findings:
        if is_allowlisted(label, text):
            allowlisted += 1
        else:
            hard_fails.append((path, lineno, label, text))

    if hard_fails:
        print("VENDOR AUDIT: FAIL")
        for path, lineno, label, text in hard_fails:
            excerpt = text if len(text) <= 220 else text[:220] + " …"
            print(f"  {path}:{lineno}: [{label}] {excerpt}")
        print(
            f"\n{len(hard_fails)} unallowlisted hit(s) across {len(paths)} file(s). "
            "Inspect each line above. If it is genuinely inert (e.g. a license-header URL or a "
            "namespace string, never a reachable network/storage call), add an ALLOWLIST entry "
            "in this script with the exact line and a one-line justification. If it looks like "
            "a real network call, storage write, or dynamic code execution, STOP and report it "
            "instead of allowlisting it.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"VENDOR AUDIT: PASS -- {len(paths)} file(s) scanned "
        f"({', '.join(str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p) for p in paths)}), "
        f"{allowlisted} allowlisted hit(s) (see ALLOWLIST in this script), 0 unallowlisted hard fails."
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
