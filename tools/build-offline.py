#!/usr/bin/env python3
"""
tools/build-offline.py -- builds dist/dustpan-offline.html, a single
self-contained HTML file for Tails / air-gapped use.

Why: Tor Browser on Tails cannot reach localhost (no dev server) and cannot
install PWAs, and ES module scripts with `import` specifiers are blocked
over file://. index.html's inline `<script type="module">` has zero
`import` statements though -- it reads window.__vendor, set by the classic
(non-module) vendor/deps.js script, instead of importing anything itself
(see the SUPPLY CHAIN comment at the top of that block). So the whole page
already runs unmodified over file:// once every *external* resource is
inlined. This script does that inlining and nothing else to app behavior;
index.html's own window.__OFFLINE_BUILD__ guards (see CLAUDE.md's "Offline
build (Tails)" section) do the rest at runtime.

What gets inlined:
  - app.js, vendor/deps.js and qr_generator.js -> inline <script> blocks
    (verbatim file contents, with any literal `</script` sequence escaped --
    see escape_script_close()).
  - index.html's strict online Content-Security-Policy meta tag -> the
    offline variant (connect-src 'none' -- this build makes zero network
    requests and, unlike the online page, cannot make any even if a bug
    tried; script-src/style-src 'unsafe-inline' because every asset above is
    now an inline block, and the srcdoc decoder iframe below inherits this
    page's CSP so its inline scripts need it too). See CLAUDE.md's Content
    Security Policy section for both variants verbatim.
  - assets/favicon.svg -> a data: URI <link>.
  - the psbt-decoder/ git submodule (index.html structure + css/style.css +
    the nine js/*.js files, ALL READ VERBATIM -- the submodule itself is
    never modified) -> composed into one self-contained HTML document,
    base64-encoded, and stashed in index.html's
    `<script type="text/plain" id="offlineDecoderDoc">` slot. index.html's
    offline branch of renderTxPreview() decodes that at runtime and hands it
    to the preview <iframe> via `srcdoc` + postMessage, since a `srcdoc`
    document has no real URL for the decoder's own js/app.js to read
    ?embed=/?network=/#hex from the way it does online. A small bootstrap
    script (DECODER_BOOTSTRAP_JS below) is inserted before the decoder's
    js/app.js to shim just enough of that so its *unmodified* IIFE behaves
    the same as it does in the online embed, driven by simulating the same
    "paste into #input, click Decode" flow a person would use.
  - window.__OFFLINE_BUILD__ = true, so index.html's runtime guards (skip
    the /api/health probe, hide the UTXO-fetch UI, offline broadcast
    hand-off, manual fee rate, etc.) activate.
  - the donate button's relative onclick target -> an absolute URL, the only
    relative navigation left once the above is inlined (so it still works if
    the user opening this file happens to have network access).

Usage:
    python3 tools/build-offline.py             # writes dist/dustpan-offline.html
    python3 tools/build-offline.py --release    # + dist/dustpan-offline.html.sha256,
                                                 # and PRINTS (does not run) the
                                                 # gpg detached-sign command

Stdlib only. Requires `git submodule update --init` to have been run once
(psbt-decoder/ must be checked out).
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML = ROOT / "index.html"
APP_JS = ROOT / "app.js"
QR_GENERATOR = ROOT / "qr_generator.js"
VENDOR_DEPS = ROOT / "vendor" / "deps.js"
FAVICON = ROOT / "assets" / "favicon.svg"
DECODER_DIR = ROOT / "psbt-decoder"
DIST_DIR = ROOT / "dist"
OUT_FILE = DIST_DIR / "dustpan-offline.html"

DONATE_URL = "https://objsal.github.io/dustpan/donate.html"

# index.html's meta CSP (script-src 'self', connect-src limited to mempool.space
# and localhost/127.0.0.1 -- the custom-backend feature's allowlist, see CLAUDE.md)
# is right for a page loaded from a server, but wrong once everything is
# inlined into one static file: 'self' would forbid running the inline
# <script> blocks this build produces, and the srcdoc decoder iframe (which
# inherits this page's CSP) needs its own inline scripts to run too. The
# offline variant instead locks connect-src to 'none' -- the strongest
# statement this build can make, since after inlining there is truly no
# network resource left to fetch.
CSP_ONLINE = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
              "img-src 'self' data: blob:; connect-src 'self' https://mempool.space "
              "http://localhost:* http://127.0.0.1:* https://localhost:* https://127.0.0.1:*; "
              "frame-src 'self'; media-src 'self'; object-src 'none'; base-uri 'none'; "
              "form-action 'none'")
CSP_OFFLINE = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
               "img-src data: blob:; connect-src 'none'; media-src 'self'; "
               "object-src 'none'; base-uri 'none'; form-action 'none'")

# Load order matches the <script> tags in psbt-decoder/index.html.
DECODER_JS_ORDER = [
    "crypto.js", "bytes.js", "encoding.js", "script.js", "tx.js",
    "psbt.js", "analysis.js", "ui.js", "app.js",
]

# Injected right before psbt-decoder's js/app.js in the composed offline
# document (build_decoder_doc() below). This string lives ONLY in the
# composed output -- it is not a change to the psbt-decoder submodule, whose
# files are read and embedded verbatim.
DECODER_BOOTSTRAP_JS = r"""(function () {
  'use strict';
  // psbt-decoder's js/app.js normally reads ?embed=1 / ?network= from
  // location.search and the PSBT hex from location.hash. An iframe loaded
  // via `srcdoc` has neither (there is no real URL) -- this shim fakes just
  // enough of URLSearchParams for app.js's UNMODIFIED IIFE to behave as if
  // embed=1 was always set, and a postMessage listener drives it the same
  // way a person pasting into #input and clicking Decode would -- the
  // decoder's own, documented entry path, not a monkeypatch of its
  // rendering logic.
  var RealUSP = window.URLSearchParams;
  var forcedNetwork = null;
  window.URLSearchParams = function (init) {
    var real = new RealUSP(init);
    return {
      has: function (k) { return k === 'embed' ? true : real.has(k); },
      get: function (k) { return k === 'network' ? forcedNetwork : real.get(k); },
    };
  };
  window.addEventListener('message', function (e) {
    var d = e.data;
    if (!d || d.type !== 'psbt-decoder:load') return;
    forcedNetwork = d.network || null;
    var netSel = document.getElementById('network');
    if (netSel && d.network && netSel.querySelector('option[value="' + d.network + '"]')) {
      netSel.value = d.network;
    }
    var input = document.getElementById('input');
    var btn = document.getElementById('decode');
    if (input && btn) { input.value = d.hex; btn.click(); }
  });
})();"""

SCRIPT_CLOSE_RE = re.compile(r"</script", re.IGNORECASE)
LOCAL_SRC_HREF_TAG_RE = re.compile(r"<(script|link)\b[^>]*>", re.IGNORECASE)
SRC_HREF_ATTR_RE = re.compile(r'\b(?:src|href)\s*=\s*"([^"]*)"', re.IGNORECASE)


def die(msg: str) -> None:
    print(f"build-offline: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        die(f"missing input file: {path}"
            + (" (psbt-decoder is a git submodule -- run `git submodule update --init`)"
               if "psbt-decoder" in str(path) else ""))
    return path.read_text(encoding="utf-8")


def escape_script_close(js: str, label: str) -> str:
    """Make `js` safe to embed verbatim inside an HTML <script>...</script>
    block. The HTML parser ends a script element on the literal,
    case-insensitive byte sequence `</script`, wherever it appears -- inside
    a JS string, a comment, or (invalidly) code -- so any occurrence has to
    be broken up before embedding, or the rest of the document after it
    would be silently swallowed into the script's text and never parsed as
    markup. `</script` -> `<\\/script` is a no-op change in *meaning* when the
    sequence sits inside a JS string or comment (the only place it could
    legally occur); if this ever fires, it is logged loudly so the escaped
    output gets a human look, not assumed silently correct.
    """
    hits = len(SCRIPT_CLOSE_RE.findall(js))
    if hits:
        print(f"build-offline: NOTE: {label} contains {hits} literal '</script' "
              f"sequence(s); escaping for embedding (`</script` -> `<\\/script`). "
              f"Verify this is inside a string/comment.", file=sys.stderr)
    return SCRIPT_CLOSE_RE.sub(lambda m: m.group(0).replace("/", "\\/"), js)


def b64_utf8(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def find_uninlined_local_refs(html: str) -> list[str]:
    """Every <script src=...> / <link ...href=...> in `html` that isn't an
    absolute http(s):// URL, a data: URI, or an in-page #fragment points at
    a local file that should have been inlined instead."""
    offenders = []
    for tag_match in LOCAL_SRC_HREF_TAG_RE.finditer(html):
        attr_match = SRC_HREF_ATTR_RE.search(tag_match.group(0))
        if not attr_match:
            continue
        target = attr_match.group(1)
        if target == "" or target.startswith(("http://", "https://", "data:", "#")):
            continue
        offenders.append(target)
    return offenders


def replace_exact(html: str, needle: str, replacement: str, what: str) -> str:
    n = html.count(needle)
    if n != 1:
        die(f"{what}: expected exactly one occurrence of {needle!r}, found {n}")
    return html.replace(needle, replacement, 1)


def build_decoder_doc() -> str:
    """Compose psbt-decoder's own index.html + css/style.css + js/*.js
    (read verbatim from the submodule -- the submodule is never written to)
    into one self-contained HTML document, with DECODER_BOOTSTRAP_JS
    inserted immediately before js/app.js."""
    decoder_index = read_text(DECODER_DIR / "index.html")
    css = read_text(DECODER_DIR / "css" / "style.css")

    decoder_index = replace_exact(
        decoder_index,
        '<link rel="stylesheet" href="css/style.css">',
        f"<style>\n{css}\n</style>",
        "psbt-decoder/index.html")

    bootstrap_block = f"<script>\n{escape_script_close(DECODER_BOOTSTRAP_JS, 'DECODER_BOOTSTRAP_JS')}\n</script>\n"

    for name in DECODER_JS_ORDER:
        js = read_text(DECODER_DIR / "js" / name)
        block = f"<script>\n{escape_script_close(js, f'psbt-decoder/js/{name}')}\n</script>"
        if name == "app.js":
            block = bootstrap_block + block
        decoder_index = replace_exact(
            decoder_index, f'<script src="js/{name}"></script>', block,
            "psbt-decoder/index.html")

    offenders = find_uninlined_local_refs(decoder_index)
    if offenders:
        die("composed psbt-decoder document still references local files: " + ", ".join(offenders))

    return decoder_index


def build() -> str:
    html = read_text(INDEX_HTML)

    flag_re = re.compile(r"<!--\s*OFFLINE:FLAG.*?-->", re.S)
    if len(flag_re.findall(html)) != 1:
        die("index.html: expected exactly one OFFLINE:FLAG placeholder comment")
    html = flag_re.sub("<script>window.__OFFLINE_BUILD__ = true;</script>", html, count=1)

    decoder_doc_b64 = b64_utf8(build_decoder_doc())
    doc_re = re.compile(r"<!--\s*OFFLINE:DECODER_DOC.*?-->", re.S)
    if len(doc_re.findall(html)) != 1:
        die("index.html: expected exactly one OFFLINE:DECODER_DOC placeholder comment")
    html = doc_re.sub(
        lambda m: f'<script type="text/plain" id="offlineDecoderDoc">{decoder_doc_b64}</script>',
        html, count=1)

    qr_js = escape_script_close(read_text(QR_GENERATOR), "qr_generator.js")
    html = replace_exact(html, '<script src="qr_generator.js"></script>',
                          f"<script>\n{qr_js}\n</script>", "index.html")

    vendor_js = escape_script_close(read_text(VENDOR_DEPS), "vendor/deps.js")
    html = replace_exact(html, '<script src="vendor/deps.js"></script>',
                          f"<script>\n{vendor_js}\n</script>", "index.html")

    # app.js's own DONATE_HREF is the only *relative* navigation target left
    # once everything above is inlined -- point it at the real deployment so
    # it still works if this device happens to be online. Done on the JS
    # source (before inlining), since the button's click handler now lives
    # in app.js, not in an onclick="" attribute (CSP forbids inline handlers
    # on the online page -- see index.html's donateBtn).
    app_js = read_text(APP_JS)
    app_js = replace_exact(
        app_js,
        "const DONATE_HREF = 'donate.html';",
        f"const DONATE_HREF = '{DONATE_URL}';",
        "app.js")
    app_js = escape_script_close(app_js, "app.js")
    html = replace_exact(html, '<script type="module" src="app.js"></script>',
                          f"<script type=\"module\">\n{app_js}\n</script>", "index.html")

    favicon_b64 = base64.b64encode(read_text(FAVICON).encode("utf-8")).decode("ascii")
    html = replace_exact(
        html,
        '<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">',
        f'<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,{favicon_b64}">',
        "index.html")

    html = replace_exact(
        html,
        f'content="{CSP_ONLINE}"',
        f'content="{CSP_OFFLINE}"',
        "index.html CSP meta tag")

    offenders = find_uninlined_local_refs(html)
    if offenders:
        die("output still references local files (not inlined): " + ", ".join(offenders))

    return html


def main() -> None:
    release = "--release" in sys.argv

    html = build()

    DIST_DIR.mkdir(exist_ok=True)
    OUT_FILE.write_text(html, encoding="utf-8")
    size = OUT_FILE.stat().st_size
    print(f"build-offline: wrote {OUT_FILE} ({size:,} bytes)")
    print("build-offline: self-check passed -- no local <script src=>/<link href=> left un-inlined")

    if release:
        digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
        sha_file = Path(str(OUT_FILE) + ".sha256")
        # `shasum -a 256` format: "<hex>  <filename>\n" (two spaces, bare filename).
        sha_file.write_text(f"{digest}  {OUT_FILE.name}\n", encoding="utf-8")
        print(f"build-offline: wrote {sha_file}")
        print()
        print("Release checklist for the human:")
        print(f"  1. Verify: shasum -a 256 -c {sha_file.name} (from inside {DIST_DIR})")
        print("  2. Sign (not run automatically -- your key, your call):")
        print(f"       gpg --armor --detach-sign {OUT_FILE}")


if __name__ == "__main__":
    main()
