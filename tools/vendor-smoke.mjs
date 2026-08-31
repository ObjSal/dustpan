#!/usr/bin/env node
// tools/vendor-smoke.mjs -- node smoke test for the vendored dependency bundle.
//
// Loads vendor/deps.js under a `window` stub (exactly as index.html will use it, just without
// a real DOM) and asserts real crypto works end to end: WIF -> P2WPKH address, xpub child
// derivation, bs58check round-trip, BBQr split/join round-trip, and that jsQR is callable.
// Also separately verifies vendor/jsqr.js (the standalone file for tools/qr-scanner.html) sets
// window.jsQR to a function when loaded as a plain <script> with no CommonJS module/exports in
// scope. Exits non-zero on any failed assertion.
//
// Run directly: node tools/vendor-smoke.mjs
// Run as part of the pipeline: python3 tools/vendor-deps.py [--verify]

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

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
// BIP32 test vector 1 master xpub (well-known, https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
const XPUB = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
let child;
let derivationThrew = false;
try {
  child = bip32.fromBase58(XPUB, bitcoin.networks.bitcoin).derive(0).derive(0);
} catch (err) {
  derivationThrew = true;
  console.error(err);
}
assert(!derivationThrew, 'bip32.fromBase58(xpub).derive(0).derive(0) does not throw');
assert(!!child && child.publicKey && child.publicKey.length === 33, 'derived child 0/0 has a 33-byte compressed public key');

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

assert(!!VERSIONS && VERSIONS['bitcoinjs-lib'] === '7.0.1' && VERSIONS['bip32'] === '4.0.0',
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
