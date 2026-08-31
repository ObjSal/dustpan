#!/usr/bin/env python3
"""
tools/vendor-deps.py -- build / verify / check / bump the vendored dependency bundle
that replaces index.html's pinned CDN (esm.sh / jsdelivr) imports.

Python 3 stdlib only (urllib, hashlib, tarfile, subprocess, json, ...). subprocess is used
to shell out to `node`/`npm`/a locally-installed `esbuild` binary -- it is NOT used to skip
the security-critical part of this script, which is the independent tarball hash check below.

WHY THIS EXISTS
    index.html imports 8 npm packages straight from a CDN with exact-pinned specifiers (see
    its SUPPLY CHAIN comment). That page handles WIF private keys, so a CDN publishing a new
    (malicious or merely broken) release under an existing tag is a real risk, and ESM imports
    from a URL can't carry Subresource Integrity hashes. This script builds a single, committed,
    human-auditable bundle (vendor/deps.js) from those same exact versions, each independently
    hash-verified against vendor/pins.json before anything is extracted or built. A later task
    rewires index.html to `<script src="vendor/deps.js">` + `window.__vendor` instead of the
    esm.sh imports; this script only builds and proves the bundle.

TWO-TRACK PROVENANCE
    Track A (this script, stdlib only): downloads the exact tarball for each of the 8 imported
    packages + the 2 node-builtin shims (see SHIMS below) + esbuild itself, computes sha512 over
    the raw bytes, and hard-fails on any mismatch against vendor/pins.json. This is the security
    gate; it runs before npm is ever invoked, on every build and every --verify.
    Track B (npm, invoked via subprocess): resolves and installs the *transitive* dependency
    tree (bech32, valibot, @noble/hashes, wif, typeforce, @scure/base, bs58, create-hash, ...)
    that esbuild needs to actually compile the bundle. npm's own fetcher independently verifies
    every package's integrity against npm registry metadata as a normal, non-optional part of
    `npm install`/`npm ci` -- this is not something this script can disable. The exact resolved
    tree is committed at vendor/package-lock.json (regenerated only in `build`/`--bump`, never
    silently rewritten by `--verify`) so a rebuild years from now resolves identically.
    Track A alone covers the 11 packages explicitly named in pins.json (the ones whose code was
    chosen and reviewed by name); Track B is deliberately not given the same one-by-one manual
    review -- pinning ~80 transitive packages individually was judged not worth the maintenance
    burden versus what npm's own integrity checking + a committed lockfile already provide. If
    that trade-off ever needs revisiting, vendor/package-lock.json is the audit trail.

NODE BUILTIN SHIMS (documented per the "document any shim" rule)
    bip32@4.0.0 -> wif@2.0.6 -> bs58check@2.1.2 -> create-hash -> md5.js -> hash-base ->
    readable-stream@2 needs the node core modules "stream" and "events". esbuild's
    --platform=browser does NOT auto-polyfill these (that's a --platform=node-only behavior),
    so the build fails with "Could not resolve stream/events -- built into node" unless something
    resolvable is installed under those exact bare specifiers. Two small, well-known, actively
    maintained pure-JS packages are pinned for this purpose (see pins.json "shims"): `events`
    (Node's own EventEmitter, backported/republished standalone) and `stream-browserify`
    (browserify's Readable/Writable/Transform polyfill). They are wired in only via esbuild's
    `--alias:stream=stream-browserify --alias:events=events` flags -- vendor/entry.mjs never
    imports them directly, and window.__vendor never exposes them.

BIP32 DEFAULT-IMPORT INTEROP NOTE
    bip32@4.0.0's CJS module sets `exports.default = exports.BIP32Factory = <fn>`. Real ESM/CJS
    interop (both Node's own and esbuild's, which replicates it) binds a *default* import to the
    whole `module.exports` object, not to `module.exports.default` -- that unwrap-to-.default
    convention is a TypeScript/webpack/babel-only convention, not part of the JS spec or Node's
    behavior. So `import BIP32Factory from 'bip32'` would bind BIP32Factory to
    `{ default: fn, BIP32Factory: fn }`, not to the callable itself. vendor/entry.mjs uses the
    *named* import `import { BIP32Factory } from 'bip32'` instead, which resolves correctly.
    (Verified: window.__vendor.BIP32Factory is a function that npm's bip32@4.0.0 says it is.)

JSQR VENDORING CHOICE (recorded per the task's "record which in MANIFEST" instruction)
    vendor/jsqr.js is NOT esbuild output. jsqr@1.4.0 ships a self-contained webpack UMD build at
    dist/jsQR.js whose fallback branch (no CommonJS `module`/`exports`, no AMD `define`) already
    does `root["jsQR"] = factory()` with `root = self`, i.e. it sets `window.jsQR` correctly as a
    plain <script> with zero wrapping needed. This script extracts that exact file directly out
    of the Track-A-verified jsqr tarball bytes (not out of npm's separately-fetched node_modules
    copy), so vendor/jsqr.js's provenance never depends on Track B at all. This also gives
    tools/qr-scanner.html a much smaller, single-purpose file instead of the ~2.8 MB deps.js.

ESBUILD VERSION STRATEGY (documented per "prefer whichever is more deterministic; document")
    `npx --yes esbuild@<pinned>` was considered and rejected: it does its own remote resolution
    of the `esbuild` dist-tag/version against the registry at invocation time and populates npx's
    own ephemeral cache, which is a second, less-controlled network+cache path alongside the one
    this script already drives for every other package. Instead, esbuild is installed the same
    way as everything else -- an exact pin in vendor/pins.json, listed in the generated
    vendor/package.json, installed via `npm ci`/`npm install` into the temp build dir, and run
    directly from `node_modules/.bin/esbuild`. Its small JS-wrapper tarball is Track-A hash
    verified like the rest; the OS/arch-specific native binary (an npm optionalDependency, e.g.
    @esbuild/darwin-arm64) is resolved and integrity-checked by npm itself (npm cannot skip this)
    -- vendor/MANIFEST records which platform package was used on the last build for reference.

Modes
    (no args) / build   -- full pipeline; writes vendor/{entry.mjs,deps.js,jsqr.js,MANIFEST,
                            package.json,package-lock.json}; hard-fails loudly on any check
                            failure (hash mismatch, npm/esbuild error, audit, smoke test).
    --verify            -- rebuilds into a temp dir *without touching any committed file*,
                            compares sha256 of the rebuilt deps.js/jsqr.js against the committed
                            ones, then runs the audit + smoke test against the COMMITTED files.
                            Green output is the proof the committed bundle matches pinned sources.
    --check             -- informational only: prints pinned vs latest-on-npm for every pin.
    --bump pkg@version  -- re-pins exactly one package (hash-verifies the new tarball AND cross-
                            checks it against the registry's own dist.integrity for that version,
                            aborting instead of pinning on any mismatch), forces a lockfile
                            refresh, rebuilds, re-runs audit + smoke test, and reminds you to run
                            tests/test_psbt_builder.py.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
TOOLS = ROOT / "tools"

PINS_PATH = VENDOR / "pins.json"
ENTRY_PATH = VENDOR / "entry.mjs"
DEPS_JS_PATH = VENDOR / "deps.js"
JSQR_JS_PATH = VENDOR / "jsqr.js"
MANIFEST_PATH = VENDOR / "MANIFEST"
PACKAGE_JSON_PATH = VENDOR / "package.json"
PACKAGE_LOCK_PATH = VENDOR / "package-lock.json"
AUDIT_SCRIPT = TOOLS / "audit-vendor.py"
SMOKE_SCRIPT = TOOLS / "vendor-smoke.mjs"

USER_AGENT = "join-psbts-vendor-deps/1.0 (+tools/vendor-deps.py)"
REGISTRY = "https://registry.npmjs.org"

ESBUILD_BUNDLE_FLAGS = ["--bundle", "--format=iife", "--platform=browser", "--target=es2022"]
ESBUILD_ALIAS_FLAGS = ["--alias:stream=stream-browserify", "--alias:events=events"]


# --------------------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------------------

def log(msg: str = "") -> None:
    print(msg, flush=True)


def fail(msg: str) -> "None":
    print(f"\nVENDOR-DEPS FAILED: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    log("+ " + " ".join(cmd) + (f"   (cwd={cwd})" if cwd else ""))
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    if check and result.returncode != 0:
        fail(f"command failed (exit {result.returncode}): {' '.join(cmd)}")
    return result


def _http_get_urllib(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        content_length = resp.headers.get("Content-Length")
        if content_length is not None and int(content_length) != len(data):
            raise IOError(f"short read from {url}: expected {content_length} bytes, got {len(data)}")
        return data


def _http_get_curl(url: str, timeout: int) -> bytes:
    # urllib.request intermittently truncates large-ish responses through this environment's
    # network proxy (observed: same URL, three different truncation points across three
    # urllib retries). curl reliably completes the same downloads, so it is the primary path;
    # urllib stays as a fallback in case curl is unavailable on some future machine. curl is
    # invoked via subprocess, which is in this script's explicitly-allowed stdlib toolset.
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        result = subprocess.run(
            ["curl", "-sS", "-L", "--fail", "-m", str(timeout),
             "-H", f"User-Agent: {USER_AGENT}", "-o", str(tmp_path), url],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise IOError(f"curl exited {result.returncode} for {url}: {result.stderr.strip()}")
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


def http_get(url: str, timeout: int = 30, retries: int = 3) -> bytes:
    """Robust GET with a couple of retries, curl first (see _http_get_curl), urllib as fallback."""
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        for getter in (_http_get_curl, _http_get_urllib):
            try:
                return getter(url, timeout)
            except (urllib.error.URLError, IOError, TimeoutError, http.client.IncompleteRead,
                    subprocess.SubprocessError, FileNotFoundError) as exc:
                last_err = exc
                log(f"  (retry {attempt}/{retries}, {getter.__name__}) download failed for {url}: {exc}")
    fail(f"could not download {url} after {retries} attempts: {last_err}")
    raise AssertionError("unreachable")


def sha512_integrity(data: bytes) -> str:
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def registry_packument(name: str, version: str | None = None) -> dict:
    path = f"{name}/{version}" if version else name
    data = http_get(f"{REGISTRY}/{path}")
    return json.loads(data)


# --------------------------------------------------------------------------------------
# pins.json
# --------------------------------------------------------------------------------------

def load_pins() -> dict:
    if not PINS_PATH.exists():
        fail(f"{PINS_PATH} does not exist")
    return json.loads(PINS_PATH.read_text())


def save_pins(pins: dict) -> None:
    PINS_PATH.write_text(json.dumps(pins, indent=2) + "\n")


def iter_pinned(pins: dict):
    """Yields (name, info, category) for every entry that gets a Track-A hash check:
    the 8 direct imports, the 2 node-builtin shims, and esbuild itself."""
    for name, info in pins["packages"].items():
        yield name, info, "package"
    for name, info in pins["shims"].items():
        if name.startswith("_"):
            continue
        yield name, info, "shim"
    yield "esbuild", pins["esbuild"], "esbuild"


# --------------------------------------------------------------------------------------
# Track A: independent tarball download + hash verification
# --------------------------------------------------------------------------------------

def verify_pins(pins: dict) -> dict[str, bytes]:
    """Downloads every pinned tarball and hard-fails on any sha512 mismatch against
    pins.json. Returns {name: raw tarball bytes} for entries that need it later
    (jsqr's dist/jsQR.js is extracted straight from these verified bytes)."""
    log("== Track A: verifying pinned tarballs against vendor/pins.json ==")
    downloaded: dict[str, bytes] = {}
    for name, info, category in iter_pinned(pins):
        data = http_get(info["tarball"])
        actual = sha512_integrity(data)
        expected = info["integrity"]
        if actual != expected:
            fail(
                f"HASH MISMATCH for {name}@{info['version']} ({category})\n"
                f"  expected: {expected}\n"
                f"  actual:   {actual}\n"
                f"  tarball:  {info['tarball']}\n"
                f"This means the bytes served for this exact version differ from what was\n"
                f"pinned. Do not proceed -- this is exactly the tampering scenario the pin\n"
                f"exists to catch. Investigate before re-running."
            )
        downloaded[name] = data
        log(f"  OK  {name}@{info['version']:<10} {actual}")
    log(f"Track A: {len(downloaded)} tarball(s) verified.\n")
    return downloaded


def extract_tar_member(tarball_bytes: bytes, member_path: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tf:
        member = tf.getmember(member_path)
        extracted = tf.extractfile(member)
        if extracted is None:
            fail(f"tar member {member_path} has no extractable content")
        return extracted.read()


# --------------------------------------------------------------------------------------
# Track B: npm-driven transitive install + esbuild
# --------------------------------------------------------------------------------------

def generate_package_json(pins: dict) -> dict:
    deps: dict[str, str] = {}
    for name, info in pins["packages"].items():
        deps[name] = info["version"]
    for name, info in pins["shims"].items():
        if name.startswith("_"):
            continue
        deps[name] = info["version"]
    deps["esbuild"] = pins["esbuild"]["version"]
    return {
        "name": "join-psbts-vendor-build",
        "private": True,
        "version": "0.0.0",
        "description": (
            "Build-only manifest for tools/vendor-deps.py. Regenerated from vendor/pins.json on "
            "every build; not used at runtime -- the app itself has no npm dependency at all."
        ),
        "dependencies": dict(sorted(deps.items())),
    }


def write_json_file(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def prepare_node_modules(build_dir: Path, pins: dict, npm_cache_dir: Path, allow_relock: bool) -> str:
    """Installs the pinned packages + their transitive deps into build_dir/node_modules.
    Returns 'ci' if the committed lockfile reproduced cleanly, 'install' if a fresh
    resolution was performed (only permitted when allow_relock is True)."""
    pkg = generate_package_json(pins)
    write_json_file(build_dir / "package.json", pkg)
    npm_cache_dir.mkdir(parents=True, exist_ok=True)

    have_lock = PACKAGE_LOCK_PATH.exists()
    if have_lock:
        shutil.copy(PACKAGE_LOCK_PATH, build_dir / "package-lock.json")
        result = subprocess.run(
            ["npm", "ci", "--no-audit", "--no-fund", "--cache", str(npm_cache_dir)],
            cwd=str(build_dir),
        )
        if result.returncode == 0:
            return "ci"
        if not allow_relock:
            fail(
                "npm ci failed against the committed vendor/package-lock.json -- the committed "
                "lockfile no longer reproduces the same install. This is exactly what --verify "
                "is supposed to catch; do not run build/--bump to silently regenerate it unless "
                "you intend to update the pin."
            )
        log("npm ci failed against the committed lockfile; regenerating it via npm install "
            "(allowed because this is a build/--bump run, not --verify).")
    elif not allow_relock:
        fail("no vendor/package-lock.json committed yet -- run `python3 tools/vendor-deps.py` "
             "(build) once before using --verify.")

    run(["npm", "install", "--no-audit", "--no-fund", "--cache", str(npm_cache_dir)], cwd=build_dir)
    shutil.copy(build_dir / "package-lock.json", PACKAGE_LOCK_PATH)
    write_json_file(PACKAGE_JSON_PATH, pkg)
    return "install"


def detect_esbuild_platform_package(build_dir: Path) -> str:
    """Best-effort: read node_modules/esbuild/package.json to find which native binary
    optionalDependency it actually invoked, for the MANIFEST's information only."""
    try:
        esbuild_pkg = json.loads((build_dir / "node_modules" / "esbuild" / "package.json").read_text())
        version = esbuild_pkg.get("version", "?")
        # esbuild's own package.json lists the resolved platform binary under optionalDependencies;
        # find the one that actually got installed under node_modules/@esbuild/*.
        esbuild_scope = build_dir / "node_modules" / "@esbuild"
        if esbuild_scope.is_dir():
            for child in sorted(esbuild_scope.iterdir()):
                return f"@esbuild/{child.name}@{version}"
        return f"esbuild@{version} (no @esbuild/* platform package found under node_modules)"
    except Exception as exc:  # pragma: no cover - purely informational
        return f"(could not determine: {exc})"


# --------------------------------------------------------------------------------------
# entry.mjs generation
# --------------------------------------------------------------------------------------

def render_entry_mjs(pins: dict) -> str:
    versions = {name: info["version"] for name, info in pins["packages"].items()}
    versions_js = ",\n".join(f"    {json.dumps(k)}: {json.dumps(v)}" for k, v in versions.items())
    return f'''\
// GENERATED by tools/vendor-deps.py from vendor/pins.json -- do not hand-edit.
// Regenerate with: python3 tools/vendor-deps.py
//
// Replaces index.html's pinned esm.sh/jsdelivr CDN imports with a single local, auditable
// bundle (vendor/deps.js). See tools/vendor-deps.py's module docstring for the full design
// rationale (two-track provenance, node-builtin shims, the bip32 default-import interop note).
import {{ Buffer }} from 'buffer';
import {{ initEccLib, address, networks, payments, crypto, Transaction, Psbt }} from 'bitcoinjs-lib';
import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs';
// bip32's CJS module sets exports.default = exports.BIP32Factory = <fn>. Real ESM/CJS interop
// binds a *default* import to the whole module.exports object, not to module.exports.default
// (that unwrap-to-.default convention is a bundler/TS convention, not the JS spec), so a default
// import here would bind BIP32Factory to {{ default, BIP32Factory }} instead of the function
// itself. The named import resolves to the actual callable.
import {{ BIP32Factory }} from 'bip32';
import {{ ECPairFactory }} from 'ecpair';
import bs58check from 'bs58check';
import {{ splitQRs, joinQRs }} from 'bbqr';
import jsQR from 'jsqr';

window.__vendor = Object.freeze({{
  Buffer,
  bitcoin: Object.freeze({{ initEccLib, address, networks, payments, crypto, Transaction, Psbt }}),
  ecc,
  BIP32Factory,
  ECPairFactory,
  bs58check,
  splitQRs,
  joinQRs,
  jsQR,
  VERSIONS: Object.freeze({{
{versions_js}
  }}),
}});
'''


# --------------------------------------------------------------------------------------
# build pipeline (shared by `build` and `--verify`)
# --------------------------------------------------------------------------------------

class BuildResult:
    def __init__(self, deps_js: bytes, jsqr_js: bytes, entry_src: str, platform_pkg: str, lock_mode: str):
        self.deps_js = deps_js
        self.jsqr_js = jsqr_js
        self.entry_src = entry_src
        self.platform_pkg = platform_pkg
        self.lock_mode = lock_mode


def run_build_pipeline(pins: dict, downloaded: dict[str, bytes], allow_relock: bool) -> BuildResult:
    with tempfile.TemporaryDirectory(prefix="vendor-deps-build-") as tmp:
        build_dir = Path(tmp)
        npm_cache_dir = build_dir.parent / (build_dir.name + "-npm-cache")

        log("== Track B: installing transitive dependencies via npm ==")
        lock_mode = prepare_node_modules(build_dir, pins, npm_cache_dir, allow_relock)
        log(f"npm install mode: {lock_mode}\n")

        entry_src = render_entry_mjs(pins)
        (build_dir / "entry.mjs").write_text(entry_src)

        esbuild_bin = build_dir / "node_modules" / ".bin" / "esbuild"
        if not esbuild_bin.exists():
            fail(f"esbuild binary not found at {esbuild_bin} after npm install")

        log("== Bundling vendor/deps.js with esbuild (no minification) ==")
        out_deps = build_dir / "deps.js"
        run(
            [str(esbuild_bin), "entry.mjs", *ESBUILD_BUNDLE_FLAGS, *ESBUILD_ALIAS_FLAGS,
             f"--outfile={out_deps.name}"],
            cwd=build_dir,
        )
        deps_js_bytes = out_deps.read_bytes()
        log(f"deps.js: {len(deps_js_bytes):,} bytes\n")

        log("== Vendoring jsqr.js directly from the Track-A-verified jsqr tarball ==")
        jsqr_js_bytes = extract_tar_member(downloaded["jsqr"], "package/dist/jsQR.js")
        log(f"jsqr.js: {len(jsqr_js_bytes):,} bytes\n")

        platform_pkg = detect_esbuild_platform_package(build_dir)

        return BuildResult(deps_js_bytes, jsqr_js_bytes, entry_src, platform_pkg, lock_mode)


def run_audit(deps_path: Path, jsqr_path: Path) -> None:
    log("== Running tools/audit-vendor.py ==")
    run([sys.executable, str(AUDIT_SCRIPT), str(deps_path), str(jsqr_path)])
    log()


def run_smoke_test() -> None:
    log("== Running node tools/vendor-smoke.mjs ==")
    run(["node", str(SMOKE_SCRIPT)])
    log()


# --------------------------------------------------------------------------------------
# MANIFEST
# --------------------------------------------------------------------------------------

def write_manifest(pins: dict, result: BuildResult) -> None:
    lines: list[str] = []
    lines.append("vendor/MANIFEST -- generated by tools/vendor-deps.py")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"Reproduce: python3 tools/vendor-deps.py --verify")
    lines.append("")
    lines.append("Pinned packages (Track A: sha512 verified against vendor/pins.json before build)")
    lines.append("-" * 88)
    for name, info in pins["packages"].items():
        lines.append(f"  {name}@{info['version']}")
        lines.append(f"    tarball:   {info['tarball']}")
        lines.append(f"    sha512:    {info['integrity']}")
    lines.append("")
    lines.append("Node-builtin shims (not imported by entry.mjs; wired via esbuild --alias, see")
    lines.append("tools/vendor-deps.py module docstring for why bip32@4.0.0 needs them)")
    lines.append("-" * 88)
    for name, info in pins["shims"].items():
        if name.startswith("_"):
            continue
        lines.append(f"  {name}@{info['version']}  (alias target for: {info['aliases']})")
        lines.append(f"    tarball:   {info['tarball']}")
        lines.append(f"    sha512:    {info['integrity']}")
    lines.append("")
    lines.append("Build tool")
    lines.append("-" * 88)
    lines.append(f"  esbuild@{pins['esbuild']['version']}")
    lines.append(f"    tarball:   {pins['esbuild']['tarball']}")
    lines.append(f"    sha512:    {pins['esbuild']['integrity']}")
    lines.append(f"    native binary actually used on this build (npm-resolved + npm-integrity-checked,")
    lines.append(f"    not independently hashed by this script -- see docstring): {result.platform_pkg}")
    lines.append("")
    lines.append("Transitive dependency tree")
    lines.append("-" * 88)
    lines.append("  Resolved and integrity-checked by npm itself (not individually pinned here);")
    lines.append("  the exact resolved tree is committed at vendor/package-lock.json. Last install")
    lines.append(f"  mode: {result.lock_mode} (ci = committed lock reproduced cleanly; install = lock")
    lines.append("  was (re)generated this run, e.g. after --bump).")
    lines.append("")
    lines.append("Output files (sha256)")
    lines.append("-" * 88)
    lines.append(f"  vendor/deps.js   {sha256_hex(result.deps_js)}  ({len(result.deps_js):,} bytes)")
    lines.append(f"  vendor/jsqr.js   {sha256_hex(result.jsqr_js)}  ({len(result.jsqr_js):,} bytes)")
    entry_bytes = result.entry_src.encode()
    lines.append(f"  vendor/entry.mjs {sha256_hex(entry_bytes)}  ({len(entry_bytes)} bytes)")
    lines.append("")
    lines.append("vendor/jsqr.js is vendored directly (not esbuild output): jsqr@1.4.0 ships a")
    lines.append("self-contained webpack UMD build at dist/jsQR.js whose no-CommonJS/no-AMD")
    lines.append("fallback branch already does `self.jsQR = factory()`, so it works unmodified as")
    lines.append("a plain <script> and needs no bundling. Extracted from the Track-A-verified")
    lines.append("jsqr tarball bytes directly (see tools/vendor-deps.py).")
    lines.append("")
    MANIFEST_PATH.write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------

def cmd_build() -> None:
    """Full build. Always allows a lockfile relock: if vendor/package.json (regenerated from
    pins.json) no longer matches the committed vendor/package-lock.json -- e.g. right after
    --bump changed a version -- `npm ci` fails fast and this falls back to `npm install`,
    which resolves fresh and rewrites the committed lockfile. When pins.json hasn't changed,
    `npm ci` against the existing lockfile succeeds and nothing is re-resolved."""
    pins = load_pins()
    downloaded = verify_pins(pins)
    result = run_build_pipeline(pins, downloaded, allow_relock=True)

    ENTRY_PATH.write_text(result.entry_src)
    DEPS_JS_PATH.write_bytes(result.deps_js)
    JSQR_JS_PATH.write_bytes(result.jsqr_js)

    run_audit(DEPS_JS_PATH, JSQR_JS_PATH)
    run_smoke_test()

    write_manifest(pins, result)

    log("=" * 88)
    log("BUILD OK")
    log(f"  vendor/deps.js   {len(result.deps_js):,} bytes  sha256={sha256_hex(result.deps_js)}")
    log(f"  vendor/jsqr.js   {len(result.jsqr_js):,} bytes  sha256={sha256_hex(result.jsqr_js)}")
    log("=" * 88)


def cmd_verify() -> None:
    if not DEPS_JS_PATH.exists() or not JSQR_JS_PATH.exists():
        fail("vendor/deps.js and/or vendor/jsqr.js do not exist yet -- run "
             "`python3 tools/vendor-deps.py` (build) first.")
    committed_deps = DEPS_JS_PATH.read_bytes()
    committed_jsqr = JSQR_JS_PATH.read_bytes()

    pins = load_pins()
    downloaded = verify_pins(pins)
    result = run_build_pipeline(pins, downloaded, allow_relock=False)

    ok = True
    if sha256_hex(result.deps_js) != sha256_hex(committed_deps):
        ok = False
        log("MISMATCH: rebuilt vendor/deps.js does not match the committed file byte-for-byte.")
        log(f"  committed sha256: {sha256_hex(committed_deps)} ({len(committed_deps):,} bytes)")
        log(f"  rebuilt   sha256: {sha256_hex(result.deps_js)} ({len(result.deps_js):,} bytes)")
    if sha256_hex(result.jsqr_js) != sha256_hex(committed_jsqr):
        ok = False
        log("MISMATCH: rebuilt vendor/jsqr.js does not match the committed file byte-for-byte.")
        log(f"  committed sha256: {sha256_hex(committed_jsqr)} ({len(committed_jsqr):,} bytes)")
        log(f"  rebuilt   sha256: {sha256_hex(result.jsqr_js)} ({len(result.jsqr_js):,} bytes)")
    if not ok:
        fail("committed vendor/ output does not reproduce from vendor/pins.json. Run "
             "`python3 tools/vendor-deps.py` (build) to regenerate, then review the diff.")

    log("MATCH: rebuilt output is byte-identical to the committed vendor/deps.js and vendor/jsqr.js.\n")

    run_audit(DEPS_JS_PATH, JSQR_JS_PATH)
    run_smoke_test()

    log("=" * 88)
    log("VERIFY OK -- committed vendor/deps.js and vendor/jsqr.js reproduce exactly from "
        "vendor/pins.json, pass the supply-chain audit, and pass the crypto smoke test.")
    log("=" * 88)


def cmd_check() -> None:
    pins = load_pins()
    rows = []
    for name, info, category in iter_pinned(pins):
        try:
            meta = registry_packument(name)
            latest = meta["dist-tags"]["latest"]
        except Exception as exc:  # pragma: no cover - network dependent, informational only
            latest = f"(lookup failed: {exc})"
        status = "up to date" if latest == info["version"] else "UPDATE AVAILABLE"
        rows.append((category, name, info["version"], latest, status))

    name_w = max(len(r[1]) for r in rows) + 2
    pinned_w = max(len(r[2]) for r in rows) + 2
    latest_w = max(len(r[3]) for r in rows) + 2
    log(f"{'category':<10}{'package':<{name_w}}{'pinned':<{pinned_w}}{'latest':<{latest_w}}status")
    log("-" * (10 + name_w + pinned_w + latest_w + 20))
    for category, name, pinned, latest, status in rows:
        log(f"{category:<10}{name:<{name_w}}{pinned:<{pinned_w}}{latest:<{latest_w}}{status}")
    log("\n(informational only -- nothing was changed; use --bump pkg@version to update a pin)")


def cmd_bump(spec: str) -> None:
    idx = spec.rfind("@")
    if idx <= 0:
        fail(f"--bump expects pkg@version (e.g. bip32@4.0.1 or @scope/pkg@1.2.3), got: {spec!r}")
    name, version = spec[:idx], spec[idx + 1:]

    pins = load_pins()
    if name in pins["packages"]:
        bucket = pins["packages"]
    elif name in pins["shims"]:
        bucket = pins["shims"]
    elif name == "esbuild":
        bucket = pins
    else:
        fail(f"{name!r} is not a currently pinned package/shim/esbuild in vendor/pins.json -- "
             f"this script only bumps existing pins, one at a time.")
        return  # unreachable, keeps type-checkers happy

    log(f"== Bumping {name} -> {version} ==")
    meta = registry_packument(name, version)
    tarball_url = meta["dist"]["tarball"]
    registry_integrity = meta["dist"].get("integrity")
    if not registry_integrity:
        fail(f"registry packument for {name}@{version} has no dist.integrity -- refusing to pin blind.")

    data = http_get(tarball_url)
    computed_integrity = sha512_integrity(data)
    if computed_integrity != registry_integrity:
        fail(
            f"registry integrity MISMATCH for {name}@{version} -- refusing to pin.\n"
            f"  registry dist.integrity: {registry_integrity}\n"
            f"  computed from tarball:   {computed_integrity}\n"
            f"This is exactly the tampering scenario pinning exists to catch; report it instead "
            f"of overriding it."
        )
    log(f"  registry dist.integrity matches the downloaded tarball's sha512: {computed_integrity}")

    old_version = pins["esbuild"]["version"] if bucket is pins else bucket[name]["version"]
    new_entry = {"version": version, "tarball": tarball_url, "integrity": computed_integrity}
    if bucket is pins:
        pins["esbuild"] = {**pins["esbuild"], **new_entry}
    else:
        bucket[name] = {**bucket[name], **new_entry}
    save_pins(pins)
    log(f"  vendor/pins.json updated: {name}@{old_version} -> {name}@{version}\n")

    cmd_build()

    log("\nReminder: run `python3 tests/test_psbt_builder.py` (and the rest of "
        "tests/run_all.py once index.html is rewired to use vendor/deps.js) before shipping "
        f"this bump of {name}.")


# --------------------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("mode", nargs="?", choices=["build"], default=None,
                        help="default mode: full build + audit + smoke test")
    group.add_argument("--verify", action="store_true",
                        help="rebuild into a temp dir, diff against committed output, re-run audit + smoke test")
    group.add_argument("--check", action="store_true",
                        help="print pinned vs latest-on-npm for every pin (no changes made)")
    group.add_argument("--bump", metavar="pkg@version",
                        help="re-pin exactly one package/shim/esbuild and rebuild")
    args = parser.parse_args()

    if args.verify:
        cmd_verify()
    elif args.check:
        cmd_check()
    elif args.bump:
        cmd_bump(args.bump)
    else:
        cmd_build()


if __name__ == "__main__":
    main()
