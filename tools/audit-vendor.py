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

FIRST-PARTY FILES (index.html, qr_generator.js, tools/qr-scanner.html): when scanned by name
(see FIRST_PARTY_BASENAMES), a separate, much smaller FIRST_PARTY_PATTERNS table is used instead
of PATTERNS -- these files legitimately call fetch/localStorage/getUserMedia/etc. themselves, so
the vendor table would be one long false-positive list. FIRST_PARTY_PATTERNS only names
primitives the app has no legitimate reason to ever use; a hit there is never allowlisted -- it
is inspected and reported. This DOES NOT diff the built bundle against source (see the module
docstring's honesty note in tools/vendor-deps.py) -- it is a pattern scan of the given file, same
mechanism as the vendor table above, just a different, first-party-appropriate pattern set.

Comment handling: a line is treated as "comment-only" (and skipped entirely) if it is inside a
/* ... */ block (tracked across lines) or its trimmed text starts with `//`, or starts with `*`
while still inside that block (a JSDoc/block-comment continuation line -- a `*`-led line OUTSIDE
an open block comment is code, not a comment, and is scanned). This correctly classifies both
esbuild's trailing "Bundled license information" block comment and short `// https://...`
explanatory comments, without hiding the one real non-comment URL hit this scan actually found
(an `xmlns="http://..."` string inside bbqr's unused SVG-render helper -- see ALLOWLIST). Known
limitation: a comment that starts after code on the same line (`foo(); /* like this */`) is not
detected as partially a comment -- the whole line is still scanned. That has not produced a
false positive against the actual bundle; if it ever does, inspect it rather than papering over
it with a broader skip.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILES = [ROOT / "vendor" / "deps.js", ROOT / "vendor" / "jsqr.js"]

# Basenames scanned with FIRST_PARTY_PATTERNS instead of PATTERNS -- see the module docstring.
FIRST_PARTY_BASENAMES = {"index.html", "qr_generator.js", "qr-scanner.html"}

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
    # -- added per the 2026-08-31 security review --
    ("Math.random",           re.compile(r'Math\.random\b')),
    # Bare (no `new`) call of Function(...) or $Function(...) -- the string-to-code-execution
    # constructor called as a plain function instead of via `new` (both forms are equivalent
    # in JS; `new Function` is already its own pattern above). The lookbehind excludes a
    # preceding `.`/word-char so a member access like `native.Function(x)` or `isFunction(x)`
    # (a type-check helper calling ITS OWN function named "...Function", not the global
    # Function constructor) is not flagged -- only `Function(` / `$Function(` used bare, the
    # way an actual call to the global constructor looks.
    ("bare Function(",        re.compile(r'(?<!new\s)(?<![\w$.])\$?Function\s*\(')),
    ("RTCPeerConnection",     re.compile(r'(?<![\w$])(?:webkit)?RTCPeerConnection\b')),
    ("Worker/importScripts",  re.compile(r'(?<![\w$])new\s+Worker\s*\(|(?<![\w$])SharedWorker\b|'
                                          r'(?<![\w$])importScripts\s*\(')),
    ("navigator.",            re.compile(r'navigator\.')),
    ("document.write",        re.compile(r'document\.write\b')),
    ("createElement(script)", re.compile(r'createElement\s*\(\s*[\'"]script', re.IGNORECASE)),
    ("WebAssembly.instantiate/compile",
                               re.compile(r'WebAssembly\.(?:instantiate|compile)\b')),
    ("location/window.open",  re.compile(r'location\.assign\s*\(|location\.replace\s*\(|'
                                          r'window\.open\s*\(')),
    ("caches.",                re.compile(r'caches\.')),
    # Computed-property evasion: obj['fe' + 'tch'] / obj[atob('ZmV0Y2g=')] /
    # obj[String.fromCharCode(...)] -- ways to spell a forbidden property name (fetch,
    # eval, ...) without the literal identifier ever appearing for the patterns above to
    # catch. Not a specific primitive; any hit here means "go read this bracket access".
    ("computed-property evasion",
                               re.compile(r'\[\s*(?:["\'][^"\']*["\']\s*\+|atob\s*\(|String\.fromCharCode)')),
]

# --------------------------------------------------------------------------------------
# allowlist -- every entry requires the exact matched line's FULL trimmed text + a one-line
# justification. Matched by (pattern label, exact equality against the full trimmed line), not
# substring containment and not by line number -- an entry survives incidental reformatting
# across rebuilds (identical line, different line number) but NOT a payload appended to an
# otherwise-allowlisted line (that changes the full-line text, so it no longer matches and is
# reported as a new, unreviewed hit instead of silently riding along). A genuinely different
# line requires a genuinely new (and re-reviewed) allowlist entry.
# --------------------------------------------------------------------------------------
ALLOWLIST: list[dict[str, str]] = [
    {
        "label": "http(s):// URL",
        "match": (
            'const s = e.getOptions(a), h3 = n.modules.size, u = n.modules.data, d = h3 + '
            's.margin * 2, g = s.color.light.a ? "<path " + r(s.color.light, "fill") + \' '
            'd="M0 0h\' + d + "v" + d + \'H0z"/>\' : "", v = "<path " + r(s.color.dark, '
            '"stroke") + \' d="\' + i2(u, h3, s.margin) + \'"/>\', c = \'viewBox="0 0 \' + d '
            '+ " " + d + \'"\', S = \'<svg xmlns="http://www.w3.org/2000/svg" \' + (s.width ? '
            '\'width="\' + s.width + \'" height="\' + s.width + \'" \' : "") + c + \' '
            'shape-rendering="crispEdges">\' + g + v + `</svg>'
        ),
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
    {
        "label": "bare Function(",
        "match": (
            'bound = Function("binder", "return function (" + joiny(boundArgs, ",") + '
            '"){ return binder.apply(this,arguments); }")(binder);'
        ),
        "justification": (
            "function-bind's polyfill path for Function.prototype.bind (used only on engines "
            "missing native .bind, i.e. never in a modern browser -- see 'Function.prototype."
            "bind || implementation' at its call site). Builds a wrapper function whose body is "
            "a fixed, hardcoded string ('return function (...){ return binder.apply(...) }') "
            "with only a comma-joined list of the bound function's OWN formal-parameter names "
            "spliced in -- never the value of any argument or any external/attacker-influenced "
            "data. Pulled transitively via get-intrinsic (see the next entry)."
        ),
    },
    {
        "label": "bare Function(",
        "match": '''return $Function('"use strict"; return (' + expressionSyntax + ").constructor;")();''',
        "justification": (
            "get-intrinsic's (pulled transitively via bip32 -> ... -> es-abstract-family "
            "packages) fallback for grabbing the intrinsic %Function% constructor on engines "
            "where it isn't otherwise reachable, gated behind 'typeof Function ... ? ... : "
            "$Function(...)' at its call site -- it only runs when the real Function global is "
            "already unavailable/restricted, and even then the constructed function body is a "
            "fixed string template ('\"use strict\"; return (<intrinsic-name>).constructor;') "
            "built from get-intrinsic's OWN internal intrinsic-name table, never from any "
            "external or attacker-influenced input."
        ),
    },
]


def is_allowlisted(label: str, line_text: str) -> bool:
    return any(entry["label"] == label and entry["match"] == line_text for entry in ALLOWLIST)


# --------------------------------------------------------------------------------------
# first-party pattern table (index.html, qr_generator.js, tools/qr-scanner.html)
# --------------------------------------------------------------------------------------
# Deliberately NOT the vendor PATTERNS table: these files legitimately call fetch(),
# localStorage, getUserMedia, WebSocket-adjacent QR-scanning code, etc. themselves, so that
# table would be one long false-positive list here. This table only names primitives the app
# has no legitimate reason to ever call -- a hit is never allowlisted, it is inspected and
# reported (see the module docstring).
FIRST_PARTY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("eval(",             re.compile(r'(?<![\w$])eval\s*\(')),
    ("new Function",      re.compile(r'\bnew\s+Function\s*\(')),
    ("bare Function(",    re.compile(r'(?<!new\s)(?<![\w$.])\$?Function\s*\(')),
    ("RTCPeerConnection", re.compile(r'(?<![\w$])(?:webkit)?RTCPeerConnection\b')),
    ("sendBeacon",        re.compile(r'(?<![\w$])sendBeacon\s*\(')),
    ("new WebSocket",     re.compile(r'\bnew\s+WebSocket\s*\(')),
    ("importScripts(",    re.compile(r'(?<![\w$])importScripts\s*\(')),
    ("document.write",    re.compile(r'document\.write\b')),
    ("Math.random",       re.compile(r'Math\.random\b')),
]


# --------------------------------------------------------------------------------------
# scanner
# --------------------------------------------------------------------------------------

def scan_file(path: Path, patterns: list[tuple[str, re.Pattern]]) -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []
    in_block_comment = False
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        line_is_comment = False

        if in_block_comment:
            # Only a line already inside an open /* */ block is a comment continuation line
            # (this is where a `*`-led JSDoc/block-comment line belongs); outside a block, a
            # line starting with `*` is ordinary code (e.g. `a * b` wrapped, or a multiply
            # expression) and must still be scanned.
            line_is_comment = True
            if "*/" in line:
                in_block_comment = False
        elif stripped.startswith("//"):
            line_is_comment = True
        elif stripped.startswith("/*"):
            line_is_comment = True
            if "*/" not in stripped[2:]:
                in_block_comment = True

        if line_is_comment:
            continue

        for label, pattern in patterns:
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

    # Each path is scanned with the vendor PATTERNS table UNLESS its basename is a known
    # first-party file, in which case it gets the much smaller FIRST_PARTY_PATTERNS table (see
    # that table's comment) and is never eligible for ALLOWLIST -- any hit there is a hard fail.
    all_findings: list[tuple[Path, int, str, str, bool]] = []
    for p in paths:
        is_first_party = p.name in FIRST_PARTY_BASENAMES
        patterns = FIRST_PARTY_PATTERNS if is_first_party else PATTERNS
        for finding in scan_file(p, patterns):
            all_findings.append((*finding, not is_first_party))

    hard_fails = []
    allowlisted = 0
    for path, lineno, label, text, allowlist_eligible in all_findings:
        if allowlist_eligible and is_allowlisted(label, text):
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
