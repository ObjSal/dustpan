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
    packages (no node-builtin shims as of the 2026-08-31 bip32@5.0.1 bump -- see NODE BUILTIN
    SHIMS below) + esbuild itself, computes sha512 over the raw bytes, and hard-fails on any
    mismatch against vendor/pins.json. This is the security gate; it runs before npm is ever
    invoked, on every build and every --verify.
    Track B (npm, invoked via subprocess): resolves and installs the *transitive* dependency
    tree (bech32, valibot, @noble/hashes, wif, @scure/base, bs58, bip174, ...) that esbuild needs
    to actually compile the bundle. npm's own fetcher independently verifies every package's
    integrity against npm registry metadata as a normal, non-optional part of
    `npm install`/`npm ci` -- this is not something this script can disable. The exact resolved
    tree is committed at vendor/package-lock.json (regenerated only in `build`/`--bump`, never
    silently rewritten by `--verify`) so a rebuild years from now resolves identically.
    Track A alone covers the 9 packages explicitly named in pins.json (the ones whose code was
    chosen and reviewed by name); Track B is deliberately not given the same one-by-one manual
    review -- pinning the ~15 remaining transitive packages individually was judged not worth the
    maintenance burden versus what npm's own integrity checking + a committed lockfile already
    provide (this was ~80 transitive packages before the 2026-08-31 bip32@4.0.0 -> 5.0.1 bump
    dropped the legacy wif@2/bs58check@2/create-hash/readable-stream@2 chain and the ljharb
    cluster it dragged in). If that trade-off ever needs revisiting, vendor/package-lock.json is
    the audit trail.

NODE BUILTIN SHIMS -- REMOVED 2026-08-31, historical note (pins.json "shims" is now empty)
    bip32@4.0.0 -> wif@2.0.6 -> bs58check@2.1.2 -> create-hash -> md5.js -> hash-base ->
    readable-stream@2 needed the node core modules "stream" and "events". esbuild's
    --platform=browser does NOT auto-polyfill these (that's a --platform=node-only behavior), so
    the build failed with "Could not resolve stream/events -- built into node" unless something
    resolvable was installed under those exact bare specifiers. Two small, well-known, actively
    maintained pure-JS packages were pinned for this purpose: `events` (Node's own EventEmitter,
    backported/republished standalone) and `stream-browserify` (browserify's
    Readable/Writable/Transform polyfill), wired in only via esbuild's
    `--alias:stream=stream-browserify --alias:events=events` flags -- vendor/entry.mjs never
    imported them directly, and window.__vendor never exposed them. The 2026-08-31 bip32@4.0.0 ->
    5.0.1 bump replaced that whole legacy chain (wif@5, @scure/base, @noble/hashes, valibot,
    uint8array-tools -- all already in the bundle via ecpair@3/bitcoinjs-lib@7) with a tree that
    needs no node builtins, so both shims and the ESBUILD_ALIAS_FLAGS that wired them in were
    removed. If a future pin ever needs a node-builtin shim again, pin and hash-verify it the
    same way (see iter_pinned()'s "shim" category and pins.json's "shims" object) rather than
    reaching for esbuild's --inject or a bare unpinned polyfill.

BIP32 DEFAULT-IMPORT INTEROP NOTE -- historical, applied to bip32@4.0.0 only
    bip32@4.0.0's CJS module set `exports.default = exports.BIP32Factory = <fn>`. Real ESM/CJS
    interop (both Node's own and esbuild's, which replicates it) binds a *default* import to the
    whole `module.exports` object, not to `module.exports.default` -- that unwrap-to-.default
    convention is a TypeScript/webpack/babel-only convention, not part of the JS spec or Node's
    behavior. So `import BIP32Factory from 'bip32'` would have bound BIP32Factory to
    `{ default: fn, BIP32Factory: fn }`, not to the callable itself, and vendor/entry.mjs used the
    *named* import `import { BIP32Factory } from 'bip32'` instead, which resolved correctly.
    bip32@5.0.1 (the 2026-08-31 bump) ships real ESM (`"type": "module"`) whose index re-exports
    `BIP32Factory` as BOTH the default AND a named export (`export { BIP32Factory as default,
    BIP32Factory }`), so this interop hazard no longer exists -- either import form now resolves
    to the same callable. vendor/entry.mjs keeps the named-import spelling for consistency with
    the ECPairFactory import beside it, not because it is still required.

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
                            Green output proves the committed bundle is CONSISTENT with the
                            committed vendor/pins.json + vendor/package-lock.json -- i.e. that
                            nobody hand-edited deps.js/jsqr.js after the fact, or bumped a pin
                            without rebuilding. It does NOT prove the lockfile itself is honest:
                            Track A only re-hashes the 9 packages named in pins.json, and Track B
                            (npm resolving vendor/package-lock.json) reproduces byte-identically
                            from a *poisoned* committed lockfile too, since npm is just replaying
                            exactly what that file says to fetch. The actual defence against a
                            bad transitive pin is human review of vendor/package-lock.json's diff
                            on every change -- see --bump below.
    --check             -- informational only: prints pinned vs latest-on-npm for every pin.
    --bump pkg@version  -- re-pins exactly one package (hash-verifies the new tarball AND cross-
                            checks it against the registry's own dist.integrity for that version,
                            aborting instead of pinning on any mismatch -- NOTE this dist.integrity
                            check is a SELF-check: both values come from the same registry fetch
                            path, so it catches transport corruption between the registry and this
                            machine, not a malicious publish already sitting on the registry. It is
                            not a second independent source), forces a lockfile refresh, rebuilds,
                            re-runs audit + smoke test, and prints the three things a human MUST
                            review before trusting the bump: the vendor/package-lock.json diff
                            stat, a before/after diff of the bundle's module inventory, and the
                            bumped version's registry publish timestamp + maintainer list. See
                            cmd_bump()'s printed "MANDATORY HUMAN REVIEW" block for the full list.
"""
from __future__ import annotations

import argparse
import base64
import difflib
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
    # --proto '=https' refuses any scheme downgrade curl might otherwise follow through a
    # redirect (e.g. an https->http bounce); --max-redirs 3 bounds how far a redirect chain
    # can wander before curl gives up, instead of following it indefinitely.
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        result = subprocess.run(
            ["curl", "-sS", "-L", "--proto", "=https", "--max-redirs", "3", "--fail", "-m", str(timeout),
             "-H", f"User-Agent: {USER_AGENT}", "-o", str(tmp_path), url],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise IOError(f"curl exited {result.returncode} for {url}: {result.stderr.strip()}")
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


# Every byte this script downloads must come from the npm registry -- no CDN, no redirect to a
# lookalike host, no "just this once" exception. This is checked in http_get() itself (the one
# function both Track A tarball verification and --bump's registry lookup/tarball fetch funnel
# through), not at each call site, so nothing can accidentally bypass it.
ALLOWED_HOST_PREFIX = "https://registry.npmjs.org/"


def http_get(url: str, timeout: int = 30, retries: int = 3) -> bytes:
    """Robust GET with a couple of retries, curl first (see _http_get_curl), urllib as fallback.
    Hard-fails on any URL that does not start with ALLOWED_HOST_PREFIX -- this script must never
    fetch bytes from anywhere but the npm registry itself."""
    if not url.startswith(ALLOWED_HOST_PREFIX):
        fail(
            f"refusing to download from a non-allowlisted host: {url!r}\n"
            f"Every download this script makes must start with {ALLOWED_HOST_PREFIX!r}. "
            f"This is a hard security boundary -- do not widen it to fetch this URL."
        )
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
    the 8 direct imports, any node-builtin shims (none as of the 2026-08-31 bip32@5.0.1
    bump -- see pins.json "shims"), and esbuild itself."""
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
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache_dir)],
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

    run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache_dir)], cwd=build_dir)
    shutil.copy(build_dir / "package-lock.json", PACKAGE_LOCK_PATH)
    write_json_file(PACKAGE_JSON_PATH, pkg)
    return "install"


def _esbuild_platform_child(build_dir: Path) -> Path | None:
    """The single node_modules/@esbuild/<platform> dir that npm resolved for this machine
    (esbuild ships its native binary as an os/cpu-gated optionalDependency, so only the
    matching one is ever installed)."""
    esbuild_scope = build_dir / "node_modules" / "@esbuild"
    if esbuild_scope.is_dir():
        for child in sorted(esbuild_scope.iterdir()):
            return child
    return None


def detect_esbuild_platform_package(build_dir: Path) -> str:
    """Best-effort: read node_modules/esbuild/package.json to find which native binary
    optionalDependency it actually invoked, for the MANIFEST's information only."""
    try:
        esbuild_pkg = json.loads((build_dir / "node_modules" / "esbuild" / "package.json").read_text())
        version = esbuild_pkg.get("version", "?")
        child = _esbuild_platform_child(build_dir)
        if child is not None:
            return f"@esbuild/{child.name}@{version}"
        return f"esbuild@{version} (no @esbuild/* platform package found under node_modules)"
    except Exception as exc:  # pragma: no cover - purely informational
        return f"(could not determine: {exc})"


def resolve_esbuild_binary(build_dir: Path) -> Path:
    """Returns the esbuild executable to run. Prefers the normal node_modules/.bin/esbuild
    symlink (npm creates bin-links unconditionally -- that is not a lifecycle script, so
    --ignore-scripts does not remove it). esbuild@0.28's JS wrapper (bin/esbuild) resolves
    its native binary from the @esbuild/<platform> optionalDependency at require-time, with
    no postinstall step, so the symlink should keep working under --ignore-scripts. If it is
    somehow missing, fall back to invoking the platform package's own native binary directly
    (its package.json "bin" field), skipping esbuild's JS wrapper entirely."""
    bin_link = build_dir / "node_modules" / ".bin" / "esbuild"
    if bin_link.exists():
        return bin_link

    log(f"  node_modules/.bin/esbuild not found at {bin_link}; falling back to the "
        f"platform package's native binary directly.")
    child = _esbuild_platform_child(build_dir)
    if child is None:
        fail(f"esbuild binary not found at {bin_link}, and no node_modules/@esbuild/<platform> "
             f"package was installed to fall back to.")
    pkg_json_path = child / "package.json"
    try:
        pkg = json.loads(pkg_json_path.read_text())
    except Exception as exc:
        fail(f"could not read {pkg_json_path} to locate the esbuild native binary: {exc}")
    bin_field = pkg.get("bin")
    if isinstance(bin_field, dict):
        # Single-entry dict keyed by the bin name (always "esbuild" for these packages).
        rel = next(iter(bin_field.values()))
    elif isinstance(bin_field, str):
        rel = bin_field
    else:
        # esbuild@0.28's @esbuild/<platform> packages ship the binary at the conventional
        # bin/esbuild path without declaring a "bin" field in package.json at all (there is
        # nothing for npm to bin-link -- these packages are optionalDependencies, not things
        # you `npx`). Fall back to that convention.
        rel = "bin/esbuild"
    native_bin = child / rel
    if not native_bin.exists():
        fail(f"esbuild native binary not found at {native_bin} (from {pkg_json_path}'s \"bin\" field).")
    log(f"  using native binary directly: {native_bin}")
    return native_bin


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
// rationale (two-track provenance, the historical node-builtin-shims and bip32 default-import
// interop notes -- both moot as of the bip32@5.0.1 bump, kept there for context).
import {{ Buffer }} from 'buffer';
import {{ initEccLib, address, networks, payments, crypto, Transaction, Psbt }} from 'bitcoinjs-lib';
import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs';
// bip32 is real ESM (`"type": "module"`) whose index re-exports BIP32Factory as both the
// default and a named export, so either import form resolves to the same callable; the named
// form is used here for consistency with the ECPairFactory import below.
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

        esbuild_bin = resolve_esbuild_binary(build_dir)

        log("== Bundling vendor/deps.js with esbuild (no minification) ==")
        out_deps = build_dir / "deps.js"
        run(
            [str(esbuild_bin), "entry.mjs", *ESBUILD_BUNDLE_FLAGS,
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
    shim_entries = [(n, i) for n, i in pins["shims"].items() if not n.startswith("_")]
    lines.append("")
    if shim_entries:
        lines.append("Node-builtin shims (not imported by entry.mjs; wired via esbuild --alias, see")
        lines.append("tools/vendor-deps.py module docstring for why they are needed)")
        lines.append("-" * 88)
        for name, info in shim_entries:
            lines.append(f"  {name}@{info['version']}  (alias target for: {info['aliases']})")
            lines.append(f"    tarball:   {info['tarball']}")
            lines.append(f"    sha512:    {info['integrity']}")
        lines.append("")
    else:
        lines.append("Node-builtin shims: none (see tools/vendor-deps.py module docstring's")
        lines.append("NODE BUILTIN SHIMS section for the historical bip32@4.0.0-era need).")
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
    lines.append("NOTE: code not named ANYWHERE above or in vendor/package-lock.json")
    lines.append("-" * 88)
    lines.append("  bbqr@1.2.0 declares zero npm dependencies (its package.json has no")
    lines.append("  \"dependencies\" field), but its published dist/bbqr.js pre-bundles its own")
    lines.append("  copies of pako@2.1.0 (gzip/deflate, licensed MIT AND Zlib) and @scure/base")
    lines.append("  (base32/base58 encoding) at PUBLISH time -- both appear inline in bbqr's own")
    lines.append("  tarball with their own embedded license comments, not as separate npm")
    lines.append("  packages. Neither is in vendor/pins.json (bbqr is the only pin that pulls")
    lines.append("  them in, inlined) nor in vendor/package-lock.json under those inlined")
    lines.append("  copies' names. (A DIFFERENT, separately-resolved @scure/base@1.2.6 -- pulled")
    lines.append("  in transitively via bip32 -> wif -- IS in package-lock.json; that is not the")
    lines.append("  same code path as bbqr's inlined copy.) Anyone treating package-lock.json as")
    lines.append("  a complete inventory of the code in vendor/deps.js will miss these two --")
    lines.append("  they are only visible in the module-inventory diff or by reading bbqr's own")
    lines.append("  published tarball.")
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
        "vendor/pins.json + vendor/package-lock.json, pass the supply-chain audit, and pass "
        "the crypto smoke test.")
    log("This proves lock<->bundle CONSISTENCY, not lockfile integrity: it re-hashes only the "
        "9 packages named in pins.json against the registry. A committed package-lock.json "
        "that already names a poisoned transitive package reproduces this same byte-identical "
        "PASS, because npm just replays what that file says to fetch. The defence against that "
        "is human review of vendor/package-lock.json's diff on every change, not this command.")
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


def _module_inventory(path: Path) -> list[str]:
    """The bundle's module inventory: esbuild's `// node_modules/<pkg>/...` comment above each
    bundled module. A package newly entering the bundle (direct or transitive) shows up here as
    one new line -- this is the human-visible signal for "--bump pulled in something extra"."""
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("  // node_modules/")]


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
    log("  NOTE: this is a SELF-check, not independent verification -- both values came from the "
        "same registry fetch path (this HTTP request), so it only catches transport corruption "
        "between the registry and this machine, not a malicious version already published to "
        "the registry. It is not a substitute for the human review below.")

    # Registry publish provenance for the human review this bump requires: fetch the full
    # packument (not the version-scoped one used above) to get time[version]; maintainers/
    # _npmUser are read from the version-scoped packument, which reflects who published this
    # specific version rather than the package's current maintainer list.
    try:
        full_meta = registry_packument(name)
        publish_time = full_meta.get("time", {}).get(version, "(not found in registry time map)")
    except Exception as exc:  # pragma: no cover - informational only
        publish_time = f"(lookup failed: {exc})"
    maintainers = meta.get("maintainers") or []
    maintainer_str = ", ".join(f"{m.get('name', '?')} <{m.get('email', '?')}>" for m in maintainers) or "(none listed)"
    npm_user = meta.get("_npmUser", {})
    publisher_str = f"{npm_user.get('name', '?')} <{npm_user.get('email', '?')}>" if npm_user else "(unknown)"

    old_version = pins["esbuild"]["version"] if bucket is pins else bucket[name]["version"]

    # "Before" snapshot of the bundle's module inventory, taken from the CURRENTLY COMMITTED
    # vendor/deps.js -- i.e. before pins.json is rewritten and cmd_build() overwrites it below.
    before_inventory = _module_inventory(DEPS_JS_PATH)
    before_lock = PACKAGE_LOCK_PATH.read_text() if PACKAGE_LOCK_PATH.exists() else ""

    new_entry = {"version": version, "tarball": tarball_url, "integrity": computed_integrity}
    if bucket is pins:
        pins["esbuild"] = {**pins["esbuild"], **new_entry}
    else:
        bucket[name] = {**bucket[name], **new_entry}
    save_pins(pins)
    log(f"  vendor/pins.json updated: {name}@{old_version} -> {name}@{version}\n")

    cmd_build()

    log("\n" + "=" * 88)
    log("MANDATORY HUMAN REVIEW -- do not ship this bump without reading all three of these")
    log("=" * 88)

    log("\n(1) vendor/package-lock.json diff --stat (the transitive tree this bump pulled in):")
    diff_stat = subprocess.run(
        ["git", "diff", "--stat", "--", "vendor/package-lock.json"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    stat_output = diff_stat.stdout.strip()
    log(stat_output if stat_output else "  (no changes -- resolved tree is identical)")
    if diff_stat.returncode != 0:
        log(f"  (git diff failed, exit {diff_stat.returncode}: {diff_stat.stderr.strip()})")

    log("\n(2) Module inventory diff (esbuild's `// node_modules/<pkg>/...` comment lines) -- "
        "any new package entering the bundle, direct or transitive, shows up here as one line:")
    after_inventory = _module_inventory(DEPS_JS_PATH)
    inventory_diff = list(difflib.unified_diff(
        before_inventory, after_inventory,
        fromfile="deps.js (before bump)", tofile="deps.js (after bump)", lineterm="",
    ))
    log("\n".join(inventory_diff) if inventory_diff else "  (no change -- identical set of bundled modules)")

    log(f"\n(3) Registry provenance for {name}@{version}:")
    log(f"  publish timestamp (time[{version!r}]): {publish_time}")
    log(f"  published by (_npmUser):     {publisher_str}")
    log(f"  current package maintainers: {maintainer_str}")

    log("\n" + "-" * 88)
    log("Before trusting this bump, a human must review, in full:")
    log("  1. The complete vendor/package-lock.json diff (not just --stat above) -- "
        "`git diff -- vendor/package-lock.json`.")
    log("  2. The module inventory diff above -- confirm every new/changed line is an expected, "
        "reviewed package.")
    log(f"  3. A green `python3 tools/audit-vendor.py` (already ran above as part of the build) "
        f"and a green unit suite (`python3 tests/test_psbt_builder.py`, and the rest of "
        f"tests/run_all.py once index.html is rewired to use vendor/deps.js).")
    log(f"  4. Whether the publish timestamp and maintainer list above look right for "
        f"{name}@{version} -- an unexpected maintainer or a suspiciously fresh publish is a "
        f"reason to stop and investigate, not to proceed.")
    log("Remember: the dist.integrity cross-check earlier in this run is a self-check "
        "(transport corruption only), and none of Track A/Track B/this bump independently "
        "re-reviews the unpinned transitive package tree -- steps 1-2 above are the actual review.")


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
