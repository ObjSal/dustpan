#!/usr/bin/env node
// tools/vendor-smoke.mjs -- node smoke test for the vendored dependency bundle.
//
// Loads vendor/deps.js under a `window` stub (exactly as index.html will use it, just without
// a real DOM) and asserts real crypto works end to end: WIF -> P2WPKH address, xpub child
// derivation against a BIP32 spec known-answer test, bs58check round-trip, BBQr split/join
// round-trip, and that jsQR is callable. It also SIGNS against published known-answer test
// vectors (RFC6979 deterministic ECDSA, BIP340 Schnorr) and checks the exact signature bytes --
// derivation-only checks would not catch a tampered nonce/signing backdoor. Also separately
// verifies vendor/jsqr.js (the standalone file for tools/qr-scanner.html) sets window.jsQR to a
// function when loaded as a plain <script> with no CommonJS module/exports in scope. Exits
// non-zero on any failed assertion.
//
// Run directly: node tools/vendor-smoke.mjs
// Run as part of the pipeline: python3 tools/vendor-deps.py [--verify]

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const DEPS_JS_PATH = path.join(ROOT, 'vendor', 'deps.js');
const JSQR_JS_PATH = path.join(ROOT, 'vendor', 'jsqr.js');

let failed = false;
function assert(cond, msg) {
  if (cond) {
    console.log('  OK   ' + msg);
  } else {
    failed = true;
    console.error('  FAIL ' + msg);
  }
}

// --- Part 1: vendor/deps.js -> window.__vendor -------------------------------------------

console.log('== vendor/deps.js ==');

// deps.js is an IIFE (no import/export statements), so it can be loaded with a plain CJS
// require() -- the nearest package.json to vendor/ has no "type": "module", so Node treats
// it as CommonJS, runs the IIFE, and it assigns to our injected global `window`.
globalThis.window = globalThis;
const require = createRequire(import.meta.url);
require(DEPS_JS_PATH);

const vendor = window.__vendor;
assert(!!vendor, 'window.__vendor was set by loading vendor/deps.js');
assert(Object.isFrozen(vendor), 'window.__vendor is frozen');

const { Buffer, bitcoin, ecc, BIP32Factory, ECPairFactory, bs58check, splitQRs, joinQRs, jsQR, VERSIONS } = vendor;

assert(typeof Buffer === 'function', 'Buffer is exposed');
assert(Buffer.from('ab', 'hex').toString('hex') === 'ab', "Buffer.from('ab','hex').toString('hex') === 'ab'");

assert(!!bitcoin && typeof bitcoin.initEccLib === 'function', 'bitcoin.initEccLib is exposed');
assert(typeof bitcoin.payments?.p2wpkh === 'function', 'bitcoin.payments.p2wpkh is exposed');
assert(typeof bitcoin.Psbt === 'function', 'bitcoin.Psbt is exposed');
assert(typeof bitcoin.Transaction === 'function', 'bitcoin.Transaction is exposed');
assert(!!bitcoin.networks?.testnet && !!bitcoin.networks?.bitcoin, 'bitcoin.networks has testnet/bitcoin');

bitcoin.initEccLib(ecc);

assert(typeof ECPairFactory === 'function', 'ECPairFactory is exposed');
const ECPair = ECPairFactory(ecc);

// Known-correct value computed with these exact pinned packages (bitcoinjs-lib@7.0.1,
// ecpair@3.0.0, @bitcoin-js/tiny-secp256k1-asmjs@2.2.3) -- the same versions the CDN imports
// this bundle replaces served, so this is the same value the page has always derived for this
// WIF on testnet.
const WIF = 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK';
const EXPECTED_P2WPKH_ADDRESS = 'tb1qczxmfezt4ucp6lwyyh2cu7e63cj20z3mja9lka';

const keyPair = ECPair.fromWIF(WIF, bitcoin.networks.testnet);
const { address } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey, network: bitcoin.networks.testnet });
assert(
  address === EXPECTED_P2WPKH_ADDRESS,
  `ECPair.fromWIF + bitcoin.payments.p2wpkh derives ${EXPECTED_P2WPKH_ADDRESS} (got ${address})`
);

assert(typeof BIP32Factory === 'function', 'BIP32Factory is exposed as a callable function (not the raw CJS module object)');
const bip32 = BIP32Factory(ecc);
// BIP32 spec TEST VECTOR 2 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
// Chain m -> Chain m/0. Test vector 1's published chains are all reachable only through a
// hardened first step (m/0'/...), which cannot be derived from a public xpub at all -- vector
// 2's path (m/0/2147483647'/1/2147483646'/2) starts with a NON-hardened child, so both "m" and
// "m/0"'s extended PUBLIC keys are published by the spec and reachable via .derive(0) alone.
// This is a known-answer test of the actual derived xpub string, not just "did it throw".
const XPUB2 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
const EXPECTED_CHILD_XPUB = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH';
let child;
let derivationThrew = false;
try {
  child = bip32.fromBase58(XPUB2, bitcoin.networks.bitcoin).derive(0);
} catch (err) {
  derivationThrew = true;
  console.error(err);
}
assert(!derivationThrew, "bip32.fromBase58(BIP32 test vector 2's xpub).derive(0) does not throw");
assert(
  !!child && child.toBase58() === EXPECTED_CHILD_XPUB,
  `bip32 derives BIP32 spec test vector 2's Chain m/0 xpub ${EXPECTED_CHILD_XPUB} (got ${child && child.toBase58()})`
);

// --- Part 1b: RFC6979 deterministic ECDSA sign (known-answer test) ------------------------
//
// ecc.sign(msgHash, privKey) must produce the exact signature bytes a correct, unbackdoored
// RFC6979 + secp256k1 implementation produces -- a KAT that only asserts "does not throw" or
// "has the right length" would pass even if e.g. the nonce (k) generation were tampered with
// to leak the private key. Expected r/s below are NOT computed with tiny-secp256k1 (the
// library under test). Derivation:
//   1. The deterministic nonce k for secp256k1, sha256, private key 1, message "Satoshi
//      Nakamoto" is a well-known published RFC6979 test vector (RFC 6979 itself has no
//      secp256k1 vectors -- this one originates from an independent Go reference
//      implementation) -- independently published and cross-confirmed in two unrelated
//      projects' own test suites:
//        k = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
//        - python-ecdsa: src/ecdsa/test_pyecdsa.py, class RFC6979.test_SECP256k1_3
//          (https://github.com/tlsfuzzer/python-ecdsa)
//        - trezor-firmware: crypto/tests/test_check.c, test_rfc6979
//          (https://github.com/trezor/trezor-firmware)
//   2. r, s were computed from that published k using the standard ECDSA equations
//      (R = k*G; r = R.x mod n; s = k^-1*(z + r*privkey) mod n) via the `ecdsa` PyPI package
//      (a separate, pure-Python implementation unrelated to tiny-secp256k1/libsecp256k1),
//      then normalized to low-S (s' = n - s, since s > n/2) because libsecp256k1 -- which
//      @bitcoin-js/tiny-secp256k1-asmjs wraps -- always returns the low-S form. (r, n-s) is a
//      standard equivalent-and-valid ECDSA signature for the same message, independently
//      re-verified with the same `ecdsa` package before being pinned here.
const RFC6979_PRIVKEY = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const RFC6979_MSG_HASH = crypto.createHash('sha256').update('Satoshi Nakamoto').digest();
const EXPECTED_RFC6979_SIG =
  '934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8' +
  '2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5';
const rfc6979Sig = Buffer.from(ecc.sign(RFC6979_MSG_HASH, RFC6979_PRIVKEY)).toString('hex');
assert(
  rfc6979Sig === EXPECTED_RFC6979_SIG,
  `ecc.sign reproduces the RFC6979 KAT for privkey=1, msg="Satoshi Nakamoto": ${EXPECTED_RFC6979_SIG} (got ${rfc6979Sig})`
);
const rfc6979Pub = ecc.pointFromScalar(RFC6979_PRIVKEY, true);
assert(
  ecc.verify(RFC6979_MSG_HASH, rfc6979Pub, Buffer.from(EXPECTED_RFC6979_SIG, 'hex')),
  'ecc.verify accepts the RFC6979 KAT signature'
);

// --- Part 1c: BIP340 Schnorr sign (known-answer test) --------------------------------------
//
// Test vector index 0 from the BIP340 spec's own published CSV
// (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv), cited directly --
// not computed with tiny-secp256k1. signSchnorr's third argument IS the BIP340 aux_rand input
// (checked in tiny-secp256k1-asmjs's lib/index.js: `signSchnorr(h, d, e)` forwards `e` as the
// wasm call's extra-entropy/aux-rand slot), so the all-zero aux_rand from the vector can be
// passed straight through for a fully deterministic sign -- no verify-only fallback needed.
const BIP340_PRIVKEY = Buffer.from('0000000000000000000000000000000000000000000000000000000000000003', 'hex');
const BIP340_MSG = Buffer.alloc(32); // all-zero, per vector index 0
const BIP340_AUX_RAND = Buffer.alloc(32); // all-zero, per vector index 0
const EXPECTED_BIP340_PUBKEY = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const EXPECTED_BIP340_SIG =
  'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821' +
  '525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0';
const bip340Sig = Buffer.from(ecc.signSchnorr(BIP340_MSG, BIP340_PRIVKEY, BIP340_AUX_RAND)).toString('hex');
assert(
  bip340Sig === EXPECTED_BIP340_SIG,
  `ecc.signSchnorr reproduces BIP340 test vector 0: ${EXPECTED_BIP340_SIG} (got ${bip340Sig})`
);
const bip340XOnlyPub = Buffer.from(ecc.pointFromScalar(BIP340_PRIVKEY, true)).slice(1);
assert(
  bip340XOnlyPub.toString('hex') === EXPECTED_BIP340_PUBKEY,
  `x-only pubkey for BIP340 vector 0's private key matches the published pubkey ${EXPECTED_BIP340_PUBKEY} (got ${bip340XOnlyPub.toString('hex')})`
);
assert(
  ecc.verifySchnorr(BIP340_MSG, bip340XOnlyPub, Buffer.from(EXPECTED_BIP340_SIG, 'hex')),
  'ecc.verifySchnorr accepts BIP340 test vector 0\'s published signature'
);

assert(typeof bs58check?.encode === 'function' && typeof bs58check?.decode === 'function', 'bs58check.encode/decode are exposed');
const roundtripInput = Buffer.from('00112233445566778899aabbccddeeff0011223344', 'hex');
const encoded = bs58check.encode(roundtripInput);
const decoded = Buffer.from(bs58check.decode(encoded));
assert(decoded.equals(roundtripInput), 'bs58check.decode(bs58check.encode(x)) === x');

assert(typeof splitQRs === 'function' && typeof joinQRs === 'function', 'splitQRs/joinQRs are exposed');
const dummyPsbt = Buffer.from('70736274ff0100', 'hex'); // magic bytes + a stray byte, not a real PSBT -- fine for a split/join round-trip
const split = splitQRs(dummyPsbt, 'P', { encoding: 'Z', maxVersion: 20 });
assert(Array.isArray(split.parts) && split.parts.length > 0, 'splitQRs(dummyPsbt) returns at least one part');
const joined = joinQRs(split.parts);
assert(Buffer.from(joined.raw).equals(dummyPsbt), 'joinQRs(splitQRs(x).parts).raw round-trips to x');

assert(typeof jsQR === 'function', 'jsQR (bundled) is a function');

assert(!!VERSIONS && VERSIONS['bitcoinjs-lib'] === '7.0.1' && VERSIONS['bip32'] === '5.0.1',
  'VERSIONS carries the pinned package versions from pins.json');

// --- Part 2: vendor/jsqr.js as a standalone <script> --------------------------------------

console.log('== vendor/jsqr.js (standalone, for tools/qr-scanner.html) ==');

const jsqrSrc = readFileSync(JSQR_JS_PATH, 'utf8');
// jsqr's UMD wrapper is: (root, factory) => { ...cjs/amd checks..., else root["jsQR"] = factory() }
// invoked as (typeof self !== 'undefined' ? self : this)(...). `new Function` bodies run with no
// closure over this module's scope (not even Node's per-CJS-file `module`/`exports` locals, which
// don't exist in an ESM file anyway), so passing an explicit `self` stand-in and reading it back
// afterwards is a faithful simulation of "plain <script>, no bundler, no CommonJS in scope".
const sandbox = {};
sandbox.self = sandbox;
const loadInSandbox = new Function('self', jsqrSrc + '\nthis.jsQR = self.jsQR;');
loadInSandbox.call(sandbox, sandbox);
assert(typeof sandbox.jsQR === 'function', 'loading vendor/jsqr.js with no module/exports/define in scope sets (self).jsQR to a function');

console.log();
if (failed) {
  console.error('VENDOR SMOKE TEST: FAILED (see FAIL lines above)');
  process.exit(1);
} else {
  console.log('VENDOR SMOKE TEST: all assertions passed');
  process.exit(0);
}
